# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
# Copyright (C) 2019 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Default configuration variables for invenio-records-permissions."""

RECORDS_PERMISSIONS_RECORD_POLICY = (
    'invenio_records_permissions.policies.RecordPermissionPolicy'
)
"""PermissionPolicy used by provided record permission factories."""
