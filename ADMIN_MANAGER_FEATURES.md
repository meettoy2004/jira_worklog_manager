# Admin and Manager Features

This document describes the admin and manager features added to the Jira Worklog Manager.

## Overview

The application now supports three user roles:
1. **Regular User** - Can manage their own Jira instances and worklogs
2. **Manager** - Can invite team members and view their worklogs
3. **Admin** - Can promote users to managers and manage all users

## Features

### Admin Features

Admins have full control over user management:

- **View all users** in the system
- **Promote users to managers** or **demote them** from manager role
- **Promote users to admin** or **remove admin role**
- Access admin dashboard at `/admin/dashboard`

#### How to Create the First Admin

After migration, create the first admin using the provided script:

```bash
python create_admin.py <username>
```

For example:
```bash
python create_admin.py john
```

### Manager Features

Managers can build and manage teams:

- **Invite team members** to their team
- **View team members** who accepted invitations
- **Remove team members** from their team
- **View team worklogs** across all Jira instances
- **Filter team reports** by date range and team member
- Access manager dashboard at `/manager/dashboard`

#### Manager Workflow

1. Admin promotes a user to manager
2. Manager invites users to their team
3. Invited users see pending invitations on their dashboard
4. Users can accept or reject invitations
5. Manager can only view worklogs of users who accepted

### Team Invitation System

The team invitation system ensures privacy:

- Users **must accept** manager invitations
- Managers can only see worklogs of **accepted** team members
- Users can **reject** invitations
- Managers can **cancel** pending invitations
- Managers can **remove** accepted members

## Database Schema

### User Table (Extended)

- `is_admin` (Boolean) - Admin role flag
- `is_manager` (Boolean) - Manager role flag

### TeamInvite Table (New)

- `id` - Primary key
- `manager_id` - Foreign key to User (the manager)
- `member_id` - Foreign key to User (the invited member)
- `status` - Invitation status: 'pending', 'accepted', or 'rejected'
- `invited_at` - Timestamp when invite was sent
- `responded_at` - Timestamp when invite was responded to

## Setup and Migration

### For New Installations

Simply run the database initialization:

```bash
python init_db.py
```

Then create the first admin:

```bash
python create_admin.py <username>
```

### For Existing Installations

1. **Run the migration script:**
   ```bash
   python migrate_db.py
   ```

2. **Create the first admin:**
   ```bash
   python create_admin.py <username>
   ```

3. **Log in as admin** and promote managers from the Admin Dashboard

## User Interface

### Navigation

The navigation bar shows role-specific links:

- **Regular users** see: Dashboard, Log Work, Reports, Jira Instances
- **Managers** also see: Manager (link to manager dashboard)
- **Admins** also see: Admin (link to admin dashboard)

User roles are displayed as badges next to the username in the navigation.

### Dashboard Updates

The main dashboard now shows:

- **Pending team invitations** (if any) with Accept/Reject buttons
- **Quick action buttons** for Manager/Admin dashboards (if applicable)

### Admin Dashboard

Located at `/admin/dashboard`, shows:

- **Total users** count
- **Total managers** count
- **Total admins** count
- **User table** with:
  - Username
  - Admin status
  - Manager status
  - Action buttons (Promote/Demote/Make Admin/Remove Admin)

### Manager Dashboard

Located at `/manager/dashboard`, shows:

- **Team members** count (accepted)
- **Pending invitations** count
- **Invite form** to add new team members
- **Team members grid** with View Reports buttons
- **Pending invitations** list
- **Rejected invitations** list (can be removed)

### Team Reports

Located at `/manager/team_reports`, shows:

- **Filter by team member** dropdown
- **Date range selector** (Today, Yesterday, 7/30/90 days, Custom)
- **Summary cards** (Total time, Team members, Projects, Date range)
- **Detailed worklogs table** with:
  - Date, Member, Issue, Summary, Time, Comment, Instance
- **Daily breakdown** of time spent
- **Project breakdown** of time spent
- **Instance breakdown** of time spent

## Security

### Authorization

- Admin routes protected by `@admin_required` decorator
- Manager routes protected by `@manager_required` decorator
- Users can only accept/reject their own invitations
- Managers can only see worklogs of accepted team members

### Data Privacy

- Regular users can only see their own Jira instances and worklogs
- Managers can only see worklogs of team members who accepted
- Team invitations can be rejected
- Users control who can see their worklogs

## API Endpoints

### Admin Routes

- `GET /admin/dashboard` - Admin dashboard
- `GET /admin/promote/<user_id>` - Promote user to manager
- `GET /admin/demote/<user_id>` - Demote user from manager
- `GET /admin/toggle-admin/<user_id>` - Toggle admin role

### Manager Routes

- `GET /manager/dashboard` - Manager dashboard
- `POST /manager/invite-member` - Send team invitation
- `GET /manager/remove-member/<invite_id>` - Remove team member
- `GET /manager/team_reports` - View team reports

### Team Invitation Routes

- `GET /accept-invite/<invite_id>` - Accept team invitation
- `GET /reject-invite/<invite_id>` - Reject team invitation

## Troubleshooting

### Migration Issues

If migration fails, check:

1. Database file permissions
2. SQLite version compatibility
3. Existing data integrity

### Cannot Access Admin Dashboard

Ensure:

1. Migration was run successfully
2. User was promoted to admin using `create_admin.py`
3. User is logged in

### Team Reports Not Showing

Check:

1. Team members have accepted invitations
2. Team members have Jira instances configured
3. Team members have logged work in the selected date range
4. Jira API credentials are correct

## Best Practices

### Admin Management

- Create a dedicated admin account
- Don't use admin account for daily work
- Limit the number of admins
- Regular audit of user roles

### Manager Management

- Managers should get user consent before inviting
- Review team membership regularly
- Remove inactive team members
- Use filters to focus on specific team members

### Team Invitations

- Accept invitations only from trusted managers
- Review what data managers can see
- Reject unwanted invitations
- Contact admin if there are issues

## Future Enhancements

Potential future features:

- Email notifications for team invitations
- Team-based analytics and metrics
- Manager hierarchy (managers of managers)
- Custom permissions and roles
- Bulk user operations
- Team templates
- Export team reports to PDF/Excel

## Support

For issues or questions:

1. Check this documentation
2. Review the error messages
3. Check application logs
4. Contact the system administrator
