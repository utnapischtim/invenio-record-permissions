# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
# Copyright (C) 2019 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Invenio Records Permissions Policies."""

from .base import BasePermissionPolicy
from .deposits import DepositPermissionPolicy
from .records import RecordPermissionPolicy, get_record_permission_policy
