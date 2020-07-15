"""
This scanner finds users that are capable of privilege escalation using APEX.
Instead of typing in your password and security token you can copy the SOQL queries.
Alternatively you import this code and use `find_users_with_apex`, which gets a logged-in simple_salesforce client.
"""
import typing
from dataclasses import dataclass

from simple_salesforce import Salesforce


# This query list all users that can PE, including lesser admins.
# We exclude users with "Manager Profiles and Permission sets" as they already have super admin rights

POTENIAL_PEABLE_USERS_SOQL_QUERY = """
SELECT
  AssigneeId,
  Assignee.Name,
  Assignee.Profile.Name
FROM PermissionSetAssignment
WHERE PermissionSet.PermissionsAuthorApex=true
  AND PermissionSet.PermissionsManageProfilesPermissionsets=false
"""

IS_USER_SUPER_ADMIN = """
SELECT AssigneeId
FROM PermissionSetAssignment
WHERE AssigneeId='{assignee_id}'
  AND PermissionSet.PermissionsManageProfilesPermissionsets=true
"""


@dataclass(frozen=True)
class SFDCUser:
    user_id: str
    name: str
    profile: str


def iterate_query(
    client: Salesforce, query: str
) -> typing.List[typing.Dict[str, typing.Any]]:
    return client.query_all(query)["records"]


def find_users_with_apex(client: Salesforce) -> typing.Iterable[SFDCUser]:
    """
    Returns a dictionary of users, with their user id as key, and their name, profile name, and whether they are admins
    """
    users = set()

    for assignment in iterate_query(client, POTENIAL_PEABLE_USERS_SOQL_QUERY):
        # Verify that the user is not a super admin. No need to worry about injections here
        if iterate_query(
            client, IS_USER_SUPER_ADMIN.format(assignee_id=assignment["AssigneeId"])
        ):
            continue

        users.add(
            SFDCUser(
                user_id=assignment["AssigneeId"],
                name=assignment["Assignee"]["Name"],
                profile=assignment["Assignee"]["Profile"]["Name"],
            )
        )

    return users


def print_pe_users(client: Salesforce) -> None:
    """
    Prints the users that can PE to stdout
    """
    print("")
    users = list(find_users_with_apex(client))
    if not users:
        print("No user can PE")
        return

    print("The following users can escalate privileges:")
    for user in find_users_with_apex(client):
        print(f"+ {user.name} ({user.user_id}) - profile {user.profile}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--username", help="Username", required=True)
    parser.add_argument("-p", "--password", help="Password", required=True)
    parser.add_argument("-t", "--token", help="Security Token", required=True)

    args = parser.parse_args()

    sfdc_client = Salesforce(
        username=args.username, password=args.password, security_token=args.token
    )
    print_pe_users(sfdc_client)
