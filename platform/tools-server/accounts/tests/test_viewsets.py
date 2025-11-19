from rest_framework.test import APITestCase
from django.urls import reverse
from accounts.models import Tenant, Team, Role, Permission, Membership, User

import factory
from factory.django import DjangoModelFactory

# --- Factories ---

class TenantFactory(DjangoModelFactory):
    class Meta:
        model = Tenant
    name = factory.Sequence(lambda n: f"Tenant{n}")
    slug = factory.Sequence(lambda n: f"tenant-{n}")

class TeamFactory(DjangoModelFactory):
    class Meta:
        model = Team
    tenant = factory.SubFactory(TenantFactory)
    name = factory.Sequence(lambda n: f"Team{n}")
    slug = factory.Sequence(lambda n: f"team-{n}")

class RoleFactory(DjangoModelFactory):
    class Meta:
        model = Role
    tenant = factory.SubFactory(TenantFactory)
    name = factory.Sequence(lambda n: f"Role{n}")

class PermissionFactory(DjangoModelFactory):
    class Meta:
        model = Permission
    resource = factory.Sequence(lambda n: f"resource{n}")
    action = "execute"

class UserFactory(DjangoModelFactory):
    class Meta:
        model = User
    email = factory.Sequence(lambda n: f"user{n}@example.com")
    password = factory.PostGenerationMethodCall('set_password', 'password')
    tenant = factory.SubFactory(TenantFactory)
    is_active = True

class MembershipFactory(DjangoModelFactory):
    class Meta:
        model = Membership
    user = factory.SubFactory(UserFactory)
    team = factory.SubFactory(TeamFactory, tenant=factory.SelfAttribute("..user.tenant"))

# --- Test Cases 

class ViewsetsTest(APITestCase):
    def setUp(self):
        # Create tenant, team, user, membership, and role for tests
        self.tenant = TenantFactory()
        self.team = TeamFactory(tenant=self.tenant)
        self.role = RoleFactory(tenant=self.tenant)
        self.user = UserFactory(tenant=self.tenant)
        self.membership = MembershipFactory(user=self.user, team=self.team)
        self.permission = PermissionFactory()
        # Use APIClient via APITestCase; force authenticate so permissions pass
        self.client.force_authenticate(user=self.user)

    def test_tenant_viewset_list(self):
        TenantFactory.create_batch(3)
        url = reverse('tenant-list')
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        # resp.data may be a list or a dict with 'results' depending on pagination
        data = resp.data
        if isinstance(data, dict) and 'results' in data:
            items = data['results']
        else:
            items = data
        self.assertGreaterEqual(len(items), 3)

    def test_team_viewset_crud(self):
        tenant = TenantFactory()
        url = reverse('team-list')
        data = {"tenant": tenant.id, "name": "A", "slug": "a"}
        resp = self.client.post(url, data)
        self.assertEqual(resp.status_code, 201)
        team_id = resp.data.get("id")
        self.assertIsNotNone(team_id)
        detail_url = reverse('team-detail', args=[team_id])
        resp = self.client.get(detail_url)
        self.assertEqual(resp.status_code, 200)
        resp = self.client.patch(detail_url, {"name": "B"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data.get("name"), "B")
        resp = self.client.delete(detail_url)
        self.assertEqual(resp.status_code, 204)

    def test_role_viewset_list(self):
        RoleFactory.create_batch(2)
        url = reverse('role-list')
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)

    def test_permission_viewset_list(self):
        PermissionFactory.create_batch(2)
        url = reverse('permission-list')
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)

    def test_membership_viewset_list(self):
        MembershipFactory.create_batch(2)
        url = reverse('membership-list')
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)

    def test_user_viewset_list(self):
        UserFactory.create_batch(2)
        url = reverse('user-list')
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)

    def test_user_me_endpoint(self):
        url = reverse('user-me')
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        # resp.data may be None in some setups; guard access
        self.assertIsNotNone(resp.data)
        self.assertEqual(resp.data.get("email"), self.user.email)

    def test_role_membership_assignment(self):
        # Assign role to membership
        self.membership.role = self.role
        self.membership.save()
        self.assertEqual(self.membership.role, self.role)
        # Check user is member of team and has role
        self.assertEqual(self.membership.user, self.user)
        self.assertEqual(self.membership.team, self.team)

    def test_permission_assignment_to_role(self):
        # Assign permission to role
        self.role.permissions.add(self.permission)
        self.role.save()
        self.assertIn(self.permission, self.role.permissions.all())

    def test_user_has_permission_via_role(self):
        # Assign role to membership and permission to role
        self.membership.role = self.role
        self.membership.save()
        self.role.permissions.add(self.permission)
        self.role.save()
        # Simulate permission check (assuming user has permission via role)
        has_permission = self.role.permissions.filter(id=self.permission.id).exists()
        self.assertTrue(has_permission)
