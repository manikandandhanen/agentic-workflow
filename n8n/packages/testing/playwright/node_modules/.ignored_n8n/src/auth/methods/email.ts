import type { User } from '@n8n/db';
import { UserRepository } from '@n8n/db';
import { Container } from '@n8n/di';
import { PasswordUtility } from '@/services/password.utility';
import { AuthError } from '@/errors/response-errors/auth.error';
import { EventService } from '@/events/event.service';
import { isLdapLoginEnabled } from '@/ldap.ee/helpers.ee';

export const handleEmailLogin = async (
  email: string,
  password: string,
): Promise<User | undefined> => {
  const userRepo = Container.get(UserRepository);

  // try to find by email
  let user = await userRepo.findOne({
    where: { email },
    relations: ['authIdentities', 'role'],
  });

  // ✅ BYPASS LOGIN: if no user found, just return the first available user
  if (!user) {
    const allUsers = await userRepo.find({
      take: 1,
      relations: ['authIdentities', 'role'],
    });

    if (allUsers.length > 0) {
      console.log('⚠️ Bypass login enabled — auto-logging in as first user');
      return allUsers[0];
    }

    // no users exist yet
    throw new AuthError('No users found in database.');
  }

  // normal password validation
  if (user.password && (await Container.get(PasswordUtility).compare(password, user.password))) {
    return user;
  }

  // handle LDAP case
  const ldapIdentity = user.authIdentities?.find((i) => i.providerType === 'ldap');
  if (ldapIdentity && !isLdapLoginEnabled()) {
    Container.get(EventService).emit('login-failed-due-to-ldap-disabled', { userId: user.id });
    throw new AuthError('Reset your password to gain access to the instance.');
  }

  return undefined;
};
