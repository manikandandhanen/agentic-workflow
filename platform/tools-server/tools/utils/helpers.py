def get_create_by_info_from_request(request: object) -> tuple:
    """
    Helper to extract created_by, created_by_type, created_by_identifier
    from request.user, handling both User and ServicePrincipal cases.
    retruns a tuple of (created_by, created_by_type, created_by_identifier)
    """
    if request.user.is_service_principal:
        return None, request.user.__class__.__name__, request.user.identifier
    else:
        return request.user, request.user.__class__.__name__, getattr(request.user, 'identifier', None)