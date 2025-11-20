import { AUTH_COOKIE_NAME, RESPONSE_ERROR_MESSAGES } from '@/constants';
import { Logger } from '@n8n/backend-common';
import { GlobalConfig } from '@n8n/config';
import { Time } from '@n8n/constants';
import type { AuthenticatedRequest, User } from '@n8n/db';
import { GLOBAL_OWNER_ROLE, InvalidAuthTokenRepository, UserRepository } from '@n8n/db';
import { Service } from '@n8n/di';
import { createHash } from 'crypto';
import type { NextFunction, Response } from 'express';
// 🔁 changed line: also import default jwt
import jwt, { JsonWebTokenError, TokenExpiredError } from 'jsonwebtoken';
import type { StringValue as TimeUnitValue } from 'ms';

import config from '@/config';
import { AuthError } from '@/errors/response-errors/auth.error';
import { ForbiddenError } from '@/errors/response-errors/forbidden.error';
import { License } from '@/license';
import { MfaService } from '@/mfa/mfa.service';
import { JwtService } from '@/services/jwt.service';
import { UrlService } from '@/services/url.service';

// === SSO config ===
//  Django create_n8n_sso_token()
const N8N_SSO_SECRET = process.env.N8N_SSO_SECRET || 'dev-n8n-sso-secret';

interface AuthJwtPayload {
	/** User Id */
	id: string;
	/** This hash is derived from email and bcrypt of password */
	hash: string;
	/** This is a client generated unique string to prevent session hijacking */
	browserId?: string;
	/** This indicates if mfa was used during the creation of this token */
	usedMfa?: boolean;
}

interface IssuedJWT extends AuthJwtPayload {
	exp: number;
}

interface PasswordResetToken {
	sub: string;
	hash: string;
}

interface CreateAuthMiddlewareOptions {
	/**
	 * If true, MFA is not enforced
	 */
	allowSkipMFA: boolean;
	/**
	 * If true, authentication becomes optional in preview mode
	 */
	allowSkipPreviewAuth?: boolean;
	/**
	 * If true, the middleware will not throw an error if authentication fails
	 * and will instead call next() regardless of authentication status.
	 * Use this for endpoints that should return different data for authenticated vs unauthenticated users.
	 */
	allowUnauthenticated?: boolean;
}

@Service()
export class AuthService {
	// The browser-id check needs to be skipped on these endpoints
	private skipBrowserIdCheckEndpoints: string[];

	constructor(
		private readonly globalConfig: GlobalConfig,
		private readonly logger: Logger,
		private readonly license: License,
		private readonly jwtService: JwtService,
		private readonly urlService: UrlService,
		private readonly userRepository: UserRepository,
		private readonly invalidAuthTokenRepository: InvalidAuthTokenRepository,
		private readonly mfaService: MfaService,
	) {
		const restEndpoint = globalConfig.endpoints.rest;
		this.skipBrowserIdCheckEndpoints = [
			// we need to exclude push endpoint because we can't send custom header on websocket requests
			`/${restEndpoint}/push`,

			// We need to exclude binary-data downloading endpoint because we can't send custom headers on `<embed>` tags
			`/${restEndpoint}/binary-data/`,

			// oAuth callback urls aren't called by the frontend. therefore we can't send custom header on these requests
			`/${restEndpoint}/oauth1-credential/callback`,
			`/${restEndpoint}/oauth2-credential/callback`,

			// Skip browser ID check for type files
			'/types/nodes.json',
			'/types/credentials.json',
		];
	}

	createAuthMiddleware({
		allowSkipMFA,
		allowSkipPreviewAuth,
		allowUnauthenticated,
	}: CreateAuthMiddlewareOptions) {
		return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
			// === SSO START ===
			const query: any = req.query || {};
			const ssoToken = typeof query.sso === 'string' ? query.sso : undefined;

			if (ssoToken && !req.user) {
				this.logger.info('[SSO] Incoming SSO request', {
					path: req.originalUrl,
					hasToken: true,
					tokenPrefix: ssoToken.substring(0, 20),
				});

				try {
					const payload = jwt.verify(ssoToken, N8N_SSO_SECRET) as any;

					const email = payload?.email as string | undefined;
					const firstName =
						(payload?.first_name as string | undefined) ??
						(payload?.given_name as string | undefined) ??
						(email ? email.split('@')[0] : 'SSO');
					const lastName =
						(payload?.last_name as string | undefined) ??
						(payload?.family_name as string | undefined) ??
						'';

					this.logger.info('[SSO] Token verified', {
						email,
						firstName,
						lastName,
						sub: payload?.sub,
						iss: payload?.iss,
						aud: payload?.aud,
						exp: payload?.exp,
					});

					if (!email) {
						this.logger.warn('[SSO] Token missing email claim – cannot authenticate');
					} else {
						let user = await this.userRepository.findOne({
							where: { email },
							relations: ['role'],
						});

						if (!user) {
							this.logger.info('[SSO] No existing user found, attempting to create one', {
								email,
							});

							const [templateUser] = await this.userRepository.find({
								take: 1,
								relations: ['role'],
							});

							if (!templateUser) {
								this.logger.warn(
									`[SSO] No template user available – cannot create user for email=${email}`,
								);
							} else {
								user = this.userRepository.create({
									email,
									firstName,
									lastName,
									password: templateUser.password,
									role: templateUser.role,
								});

								user = await this.userRepository.save(user);
								this.logger.info('[SSO] Created new n8n user from SSO', {
									email: user.email,
									id: user.id,
									role: user.role,
								});
							}
						} else {
							this.logger.info('[SSO] Found existing user for SSO', {
								email: user.email,
								id: user.id,
								role: user.role,
							});
						}

						if (user) {
							this.logger.info('[SSO] Issuing n8n auth cookie for SSO user', {
								email: user.email,
								id: user.id,
							});

							this.issueCookie(res, user, false, (req as any).browserId);

							req.user = user;
							req.authInfo = { usedMfa: false };

							const cleanUrl = req.originalUrl.replace(
								/([?&])sso=[^&]+(&?)/,
								(_match, sep, tail) => (tail === '&' ? sep : ''),
							);

							this.logger.info('[SSO] Redirecting after SSO login', {
								from: req.originalUrl,
								to: cleanUrl || req.path || '/',
							});

							res.redirect(cleanUrl || req.path || '/');
							return;
						}
					}
				} catch (error) {
					this.logger.warn('[SSO] Token verification failed', {
						error: (error as Error).message,
					});
					// fall through to normal auth
				}
			}
			// === SSO END ===

			const token = req.cookies[AUTH_COOKIE_NAME];

			if (token) {
				this.logger.debug('[AUTH] Cookie token present, resolving JWT');

				try {
					const isInvalid = await this.invalidAuthTokenRepository.existsBy({ token });
					if (isInvalid) {
						this.logger.warn('[AUTH] Token is marked as invalid in DB');
						throw new AuthError('Unauthorized');
					}

					const [user, { usedMfa }] = await this.resolveJwt(token, req, res);
					const mfaEnforced = this.mfaService.isMFAEnforced();

					this.logger.debug('[AUTH] Resolved JWT successfully', {
						userId: user.id,
						email: user.email,
						usedMfa,
					});

					if (mfaEnforced && !usedMfa && !allowSkipMFA) {
						if (user.mfaEnabled) {
							this.logger.warn('[AUTH] MFA enforced but not used for this token', {
								userId: user.id,
							});
							throw new AuthError('MFA not used during authentication');
						} else {
							if (allowUnauthenticated) {
								return next();
							}

							res.status(401).json({
								status: 'error',
								message: 'Unauthorized',
								mfaRequired: true,
							});
							return;
						}
					}

					req.user = user;
					req.authInfo = {
						usedMfa,
					};
				} catch (error) {
					if (error instanceof JsonWebTokenError || error instanceof AuthError) {
						this.logger.warn('[AUTH] JWT invalid or auth error, clearing cookie', {
							error: (error as Error).message,
						});
						this.clearCookie(res);
					} else {
						this.logger.error('[AUTH] Unexpected error while resolving JWT', {
							error: (error as Error).message,
						});
						throw error;
					}
				}
			} else {
				this.logger.debug('[AUTH] No auth cookie present on request', {
					path: req.originalUrl,
					method: req.method,
				});
			}

			const isPreviewMode = process.env.N8N_PREVIEW_MODE === 'true';
			const shouldSkipAuth = (allowSkipPreviewAuth && isPreviewMode) || allowUnauthenticated;

			if (req.user) next();
			else if (shouldSkipAuth) next();
			else {
				this.logger.debug('[AUTH] Request unauthenticated and not allowed unauthenticated access', {
					path: req.originalUrl,
				});
				res.status(401).json({ status: 'error', message: 'Unauthorized' });
			}
		};
	}

	clearCookie(res: Response) {
		res.clearCookie(AUTH_COOKIE_NAME);
	}

	async invalidateToken(req: AuthenticatedRequest) {
		const token = req.cookies[AUTH_COOKIE_NAME];
		if (!token) return;
		try {
			const { exp } = this.jwtService.decode(token);
			if (exp) {
				await this.invalidAuthTokenRepository.insert({
					token,
					expiresAt: new Date(exp * 1000),
				});
			}
		} catch (e) {
			this.logger.warn('failed to invalidate auth token', { error: (e as Error).message });
		}
	}

	issueCookie(res: Response, user: User, usedMfa: boolean, browserId?: string) {
		// TODO: move this check to the login endpoint in AuthController
		// If the instance has exceeded its user quota, prevent non-owners from logging in
		const isWithinUsersLimit = this.license.isWithinUsersLimit();
		if (
			config.getEnv('userManagement.isInstanceOwnerSetUp') &&
			user.role.slug !== GLOBAL_OWNER_ROLE.slug &&
			!isWithinUsersLimit
		) {
			throw new ForbiddenError(RESPONSE_ERROR_MESSAGES.USERS_QUOTA_REACHED);
		}

		const token = this.issueJWT(user, usedMfa, browserId);
		const { samesite, secure } = this.globalConfig.auth.cookie;
		res.cookie(AUTH_COOKIE_NAME, token, {
			maxAge: this.jwtExpiration * Time.seconds.toMilliseconds,
			httpOnly: true,
			sameSite: samesite,
			secure,
		});
	}

	issueJWT(user: User, usedMfa: boolean = false, browserId?: string) {
		const payload: AuthJwtPayload = {
			id: user.id,
			hash: this.createJWTHash(user),
			browserId: browserId && this.hash(browserId),
			usedMfa,
		};
		return this.jwtService.sign(payload, {
			expiresIn: this.jwtExpiration,
		});
	}

	async resolveJwt(
		token: string,
		req: AuthenticatedRequest,
		res: Response,
	): Promise<[User, { usedMfa: boolean }]> {
		const jwtPayload: IssuedJWT = this.jwtService.verify(token, {
			algorithms: ['HS256'],
		});

		// TODO: Use an in-memory ttl-cache to cache the User object for upto a minute
		const user = await this.userRepository.findOne({
			where: { id: jwtPayload.id },
			relations: ['role'],
		});

		if (
			// If not user is found
			!user ||
			// or, If the user has been deactivated (i.e. LDAP users)
			user.disabled ||
			// or, If the email or password has been updated
			jwtPayload.hash !== this.createJWTHash(user)
		) {
			throw new AuthError('Unauthorized');
		}

		// Check if the token was issued for another browser session, ignoring the endpoints that can't send custom headers
		const endpoint = req.route ? `${req.baseUrl}${req.route.path}` : req.baseUrl;
		if (req.method === 'GET' && this.skipBrowserIdCheckEndpoints.includes(endpoint)) {
			this.logger.debug(`Skipped browserId check on ${endpoint}`);
		} else if (
			jwtPayload.browserId &&
			(!req.browserId || jwtPayload.browserId !== this.hash(req.browserId))
		) {
			this.logger.warn(`browserId check failed on ${endpoint}`);
			throw new AuthError('Unauthorized');
		}

		if (jwtPayload.exp * 1000 - Date.now() < this.jwtRefreshTimeout) {
			this.logger.debug('JWT about to expire. Will be refreshed');
			this.issueCookie(res, user, jwtPayload.usedMfa ?? false, req.browserId);
		}

		return [user, { usedMfa: jwtPayload.usedMfa ?? false }];
	}

	generatePasswordResetToken(user: User, expiresIn: TimeUnitValue = '20m') {
		const payload: PasswordResetToken = { sub: user.id, hash: this.createJWTHash(user) };
		return this.jwtService.sign(payload, { expiresIn });
	}

	generatePasswordResetUrl(user: User) {
		const instanceBaseUrl = this.urlService.getInstanceBaseUrl();
		const url = new URL(`${instanceBaseUrl}/change-password`);

		url.searchParams.append('token', this.generatePasswordResetToken(user));
		url.searchParams.append('mfaEnabled', user.mfaEnabled.toString());

		return url.toString();
	}

	async resolvePasswordResetToken(token: string): Promise<User | undefined> {
		let decodedToken: PasswordResetToken;
		try {
			decodedToken = this.jwtService.verify(token);
		} catch (e) {
			if (e instanceof TokenExpiredError) {
				this.logger.debug('Reset password token expired', { token });
			} else {
				this.logger.debug('Error verifying token', { token });
			}
			return;
		}

		const user = await this.userRepository.findOne({
			where: { id: decodedToken.sub },
			relations: ['authIdentities', 'role'],
		});

		if (!user) {
			this.logger.debug(
				'Request to resolve password token failed because no user was found for the provided user ID',
				{ userId: decodedToken.sub, token },
			);
			return;
		}

		if (decodedToken.hash !== this.createJWTHash(user)) {
			this.logger.debug('Password updated since this token was generated');
			return;
		}

		return user;
	}

	createJWTHash({ email, password, mfaEnabled, mfaSecret }: User) {
		const payload = [email, password];
		if (mfaEnabled && mfaSecret) {
			payload.push(mfaSecret.substring(0, 3));
		}
		return this.hash(payload.join(':')).substring(0, 10);
	}

	private hash(input: string) {
		return createHash('sha256').update(input).digest('base64');
	}

	/** How many **milliseconds** before expiration should a JWT be renewed. */
	get jwtRefreshTimeout() {
		const { jwtRefreshTimeoutHours, jwtSessionDurationHours } = this.globalConfig.userManagement;
		if (jwtRefreshTimeoutHours === 0) {
			return Math.floor(jwtSessionDurationHours * 0.25 * Time.hours.toMilliseconds);
		} else {
			return Math.floor(jwtRefreshTimeoutHours * Time.hours.toMilliseconds);
		}
	}

	/** How many **seconds** is an issued JWT valid for. */
	get jwtExpiration() {
		return this.globalConfig.userManagement.jwtSessionDurationHours * Time.hours.toSeconds;
	}
}
