# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
# Copyright (C) 2019 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Invenio Records Permissions Generators."""

import json
import operator
from functools import reduce
from itertools import chain

from elasticsearch_dsl.query import Q
from flask import g
from flask_principal import ActionNeed, UserNeed, RoleNeed
from invenio_access.permissions import any_user, superuser_access
from invenio_files_rest.models import Bucket, ObjectVersion
from invenio_records_files.api import Record
from invenio_records_files.models import RecordsBuckets

from flask_login import current_user
from invenio_records_permissions.setup import ip_ranges, single_ips


class Generator(object):
    """Parent class mapping the context when an action is allowed or denied.

    It does so by *generating* "needed" and "excluded" Needs. At the search
    level it implements the *query filters* to restrict the search.

    Any context inherits from this class.
    """

    def needs(self, **kwargs):
        """Enabling Needs."""
        return []

    def excludes(self, **kwargs):
        """Preventing Needs."""
        return []

    def query_filter(self, **kwargs):
        """Elasticsearch filters."""
        return []


class RecordIp(Generator):
    """
    If the user_ip is not among the allowed IPs (see setup.py), 
    all records containing 'ip_single' in 'applied_restrictions' will not be listed
    """

    def needs(self, record=None, **rest_over):
        """ Allow access to records API with 'ip_single' in applied_restrictions """

        # Restriction not applied to records without ip_single in applied_restrictions array
        if "ip_single" not in record.get("applied_restrictions", []):
            return [any_user]

        # Checks if the user IP is allowed
        visible = self.check_permission()

        # View record if ip_single is among applied_restrictions and there is an IP match
        if visible:
            return [any_user]
        return []

    def query_filter(self, *args, **kwargs):

        # Checks if the user IP is allowed
        visible = self.check_permission()

        # If the user's IP is not among the allowed IPs
        if not visible:
            # If the record contains 'ip_single' in 'applied_restrictions' will not be seen
            return ~Q("match", **{"applied_restrictions": "ip_single"})

        # Lists all records
        return Q("match_all")

    def check_permission(self):
        # The user needs to be logged in
        if "current_login_ip" not in vars(current_user):
            return False

        # Get user's ip address
        user_ip = str(current_user.current_login_ip)

        # Checks if the user IP is among single IPs
        if user_ip in single_ips:
            return True
        return False


class RecordIpRange(Generator):
    """
    If the user_ip is not in an IP range (see setup.py), 
    all records containing 'ip_range' in 'applied_restrictions' will not be listed
    """

    def needs(self, record=None, **rest_over):
        # Restriction not applied to records without ip_single in applied_restrictions array
        if "ip_range" not in record.get("applied_restrictions", []):
            return [any_user]

        # Checks if the user IP is allowed
        visible = self.check_permission()

        # View record if ip_single is among applied_restrictions and there is an IP match
        if visible:
            return [any_user]
        return []

    def query_filter(self, *args, **kwargs):

        # Checks if the user IP is allowed
        visible = self.check_permission()

        if not visible:
            # Records contains 'ip_range' in 'applied_restrictions' will not be listed in the search page
            return ~Q("match", **{"applied_restrictions": "ip_range"})

        # Lists all records
        return Q("match_all")

    def check_permission(self):

        # The user needs to be logged in
        if "current_login_ip" not in vars(current_user):
            return False

        # Get user's ip address
        user_ip = str(current_user.current_login_ip)

        # Checks if the user IP is in an ip_range
        for ip_range in ip_ranges:
            ip_start = ip_range[0]
            ip_end = ip_range[1]
            if user_ip >= ip_start and user_ip <= ip_end:
                return True

        return False


class RecordOwners(Generator):
    """
    Allows access: 
        - when 'owners' is in applied_restrictions field
        AND
        - when the user_id is in owners
    """

    def needs(self, record=None, **kwargs):
        # Allow access to records with 'owners' in applied_restrictions
        if "owners" not in record.get("applied_restrictions", []):
            return [any_user]
        return [UserNeed(owner) for owner in record.get("owners", [])]

    def query_filter(self, **kwargs):
        """Filters for current identity as owner."""

        # Contains logged-in user information
        provides = g.identity.provides

        # Specify which restriction will be applied (owners)
        matches = {"applied_restrictions": "owners"}

        # Gets the user id
        for need in provides:
            if need.method == "id":
                matches["_owners"] = need.value
                break

        # Queries Elasticsearch -> both user_id and applied_restrictions need to match
        queries = [Q("match", **{match: f"{matches[match]}"}) for match in matches]
        return reduce(operator.and_, queries)


class RecordGroups(Generator):
    """
    Allows access: 
        - when 'groups' is in applied_restrictions field
        AND
        - when the user belongs to at least one group_restrictions
    """

    def needs(self, record=None, **rest_over):
        # Allow access to records with 'groups' in applied_restrictions
        if "groups" not in record.get("applied_restrictions", []):
            return [any_user]
        return [RoleNeed(group) for group in record.get("group_restrictions", [])]

    def query_filter(self, *args, **kwargs):

        # Contains logged-in user information
        provides = g.identity.provides

        # Specify which restriction will be applied (groups)
        query_restrictions = Q("match", **{"applied_restrictions": "groups"})

        # Get all user's groups
        matches = {}
        for need in provides:
            if need.method == "role":
                matches["group_restrictions"] = need.value

        # If the user belongs to no group show no record
        if len(matches) == 0:
            return ~Q("match_all")

        # Queries Elasticsearch:
        #       - applied_restrictions need to have 'groups'
        #       - at least one group need to match
        query_matches = [
            Q("match", **{match: f"{matches[match]}"}) for match in matches
        ]
        return query_restrictions + reduce(operator.or_, query_matches)


class AnyUser(Generator):
    """Allows any user."""

    def __init__(self):
        """Constructor."""
        super(AnyUser, self).__init__()

    def needs(self, **kwargs):
        """Enabling Needs."""
        return [any_user]

    def query_filter(self, **kwargs):
        """Match all in search."""
        # TODO: Implement with new permissions metadata
        return Q("match_all")


class SuperUser(Generator):
    """Allows super users."""

    def __init__(self):
        """Constructor."""
        super(SuperUser, self).__init__()

    def needs(self, **kwargs):
        """Enabling Needs."""
        return [superuser_access]

    def query_filter(self, record=None, **kwargs):
        """Filters for current identity as super user."""
        # TODO: Implement with new permissions metadata
        return []


class Disable(Generator):
    """Denies ALL users including super users."""

    def __init__(self):
        """Constructor."""
        super(Disable, self).__init__()

    def excludes(self, **kwargs):
        """Preventing Needs."""
        return [any_user]

    def query_filter(self, **kwargs):
        """Match None in search."""
        return ~Q("match_all")


class Admin(Generator):
    """Allows users with admin-access (different from superuser-access)."""

    def __init__(self):
        """Constructor."""
        super(Admin, self).__init__()

    def needs(self, **kwargs):
        """Enabling Needs."""
        return [ActionNeed("admin-access")]


# class RecordOwners(Generator):
#     """Allows record owners."""

#     def needs(self, record=None, **kwargs):
#         """Enabling Needs."""
#         return [UserNeed(owner) for owner in record.get("owners", [])]

#     def query_filter(self, record=None, **kwargs):
#         """Filters for current identity as owner."""
#         # TODO: Implement with new permissions metadata
#         provides = g.identity.provides
#         for need in provides:
#             if need.method == "id":
#                 return Q("term", owners=need.value)
#         return []


class AnyUserIfPublic(Generator):
    """Allows any user if record is public.

    TODO: Revisit when dealing with files.
    """

    def needs(self, record=None, **rest_over):
        """Enabling Needs."""
        is_restricted = record and record.get("_access", {}).get(
            "metadata_restricted", False
        )
        return [any_user] if not is_restricted else []

    def excludes(self, record=None, **rest_over):
        """Preventing Needs."""
        return []

    def query_filter(self, *args, **kwargs):
        """Filters for non-restricted records."""
        # TODO: Implement with new permissions metadata
        return Q("term", **{"_access.metadata_restricted": False})


class AllowedByAccessLevel(Generator):
    """Allows users/roles/groups that have an appropriate access level."""

    # TODO: Implement other access levels:
    # 'metadata_reader'
    # 'files_reader'
    # 'files_curator'
    # 'admin'
    ACTION_TO_ACCESS_LEVELS = {
        "create": [],
        "read": ["metadata_curator"],
        "update": ["metadata_curator"],
        "delete": [],
    }

    def __init__(self, action="read"):
        """Constructor."""
        self.action = action

    def needs(self, record=None, **kwargs):
        """Enabling UserNeeds for each person."""
        if not record:
            return []

        access_levels = AllowedByAccessLevel.ACTION_TO_ACCESS_LEVELS.get(
            self.action, []
        )

        # Name "identity" is used bc it correlates with flask-principal
        # identity while not being one.
        allowed_identities = chain.from_iterable(
            [
                record.get("internal", {})
                .get("access_levels", {})
                .get(access_level, [])
                for access_level in access_levels
            ]
        )

        return [
            UserNeed(identity.get("id"))
            for identity in allowed_identities
            if identity.get("scheme") == "person" and identity.get("id")
            # TODO: Implement other schemes
        ]

    def query_filter(self, *args, **kwargs):
        """Search filter for the current user with this generator."""
        id_need = next(
            (need for need in g.identity.provides if need.method == "id"), None
        )

        if not id_need:
            return []

        # To get the record in the search results, the access level must
        # have been put in the 'read' array
        read_levels = AllowedByAccessLevel.ACTION_TO_ACCESS_LEVELS.get("read", [])

        queries = [
            Q(
                "term",
                **{
                    "internal.access_levels.{}".format(access_level): {
                        "scheme": "person",
                        "id": id_need.value
                        # TODO: Implement other schemes
                    }
                },
            )
            for access_level in read_levels
        ]

        return reduce(operator.or_, queries)


#
# | Meta Restricted | Files Restricted | Access Right | Result |
# |-----------------|------------------|--------------|--------|
# |       True      |       True       |   Not Open   |  False |
# |-----------------|------------------|--------------|--------|
# |       True      |       True       |     Open     |  False | # Inconsistent
# |-----------------|------------------|--------------|--------|
# |       True      |       False      |   Not Open   |  False | # Inconsistent
# |-----------------|------------------|--------------|--------|
# |       True      |       False      |     Open     |  False | # Inconsistent
# |-----------------|------------------|--------------|--------|
# |       False     |       True       |   Not Open   |  False | ??Inconsistent
# |-----------------|------------------|--------------|--------|
# |       False     |       True       |     Open     |  False |
# |-----------------|------------------|--------------|--------|
# |       False     |       False      |   Not Open   |  False | # Inconsistent
# |-----------------|------------------|--------------|--------|
# |       False     |       False      |     Open     |  True  |
# |-----------------|------------------|--------------|--------|
#
