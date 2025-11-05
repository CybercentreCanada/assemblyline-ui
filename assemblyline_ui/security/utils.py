import json
import re

from assemblyline.common.str_utils import safe_str
from assemblyline.odm.models.user import USER_TYPE_DEP

from assemblyline_ui.config import CLASSIFICATION as Classification


def process_autoproperties(auto_properties, profile_data, default_classification):
    # Compute access, user_type, roles and classification using auto_properties
    access = True
    access_set = False
    user_type = []
    roles = []
    groups = []
    remove_roles = set()
    quotas = {}
    classification = Classification.UNRESTRICTED
    organization = None
    default_metadata = {}

    if not auto_properties:
        return access, user_type, roles, organization, groups, remove_roles, quotas, default_classification, default_metadata

    for auto_prop in auto_properties:
        if auto_prop.type == "access" and not access_set:
            # Set default access value for access pattern
            access = auto_prop.value[0].lower() != "true"
            access_set = True

        # Get values for field
        field_data = profile_data.get(auto_prop.field, None)
        if not isinstance(field_data, list):
            field_data = [field_data]
        field_data = [safe_str(x) for x in field_data]

        # Analyse field values
        for value in field_data:
            # If there is no value, no need to do any tests
            if value == "None":
                continue

            # Check access
            if auto_prop.type == "access":
                if re.match(auto_prop.pattern, value) is not None:
                    access = auto_prop.value[0].lower() == "true"
                    break

            # Append user type from matching patterns
            elif auto_prop.type == "type":
                if re.match(auto_prop.pattern, value):
                    user_type.extend(auto_prop.value)
                    break

            # Append roles from matching patterns
            elif auto_prop.type == "role":
                if re.match(auto_prop.pattern, value):
                    for ap_val in auto_prop.value:
                        # Did we just put an account type in the roles field?
                        if ap_val in USER_TYPE_DEP:
                            # Support of legacy configurations
                            user_type.append(ap_val)
                            roles = list(set(roles).union(USER_TYPE_DEP[ap_val]))
                        else:
                            roles.append(ap_val)
                    break

            # Remove roles from matching patterns
            elif auto_prop.type == "remove_role":
                if re.match(auto_prop.pattern, value):
                    for ap_val in auto_prop.value:
                        remove_roles.add(ap_val)
                    break

            # Compute classification from matching patterns
            elif auto_prop.type == "classification":
                if re.match(auto_prop.pattern, value):
                    for ap_val in auto_prop.value:
                        classification = Classification.build_user_classification(classification, ap_val)
                    break

            # Append groups from matching patterns
            elif auto_prop.type == "group":
                group_match = re.match(auto_prop.pattern, value)
                if group_match:
                    for group_value in auto_prop.value:
                        for index, gm_value in enumerate(group_match.groups()):
                            group_value = group_value.replace(f"${index+1}", gm_value)
                        groups.append(group_value)

            # Append multiple groups from a single matching pattern
            elif auto_prop.type == "multi_group":
                all_matches = re.findall(auto_prop.pattern, value)
                for group_match in all_matches:
                    for group_value in auto_prop.value:
                        if not isinstance(group_match, tuple):
                            group_match = (group_match)
                        for index, gm_value in enumerate(group_match):
                            group_value = group_value.replace(f"${index+1}", gm_value)
                        if group_value not in groups:
                            groups.append(group_value)

            elif auto_prop.type == "organization":
                org_match = re.match(auto_prop.pattern, value)
                if org_match:
                    org_value = auto_prop.value[0]
                    for index, gm_value in enumerate(org_match.groups()):
                        org_value = org_value.replace(f"${index+1}", gm_value)

                    if Classification.dynamic_groups and Classification.dynamic_groups_type in ['groups', 'all']:
                        # Ensure organization is uppercase if dynamic groups are enabled
                        org_value = org_value.upper()

                    organization = org_value

            elif auto_prop.type == "default_metadata":
                metadata_match = re.match(auto_prop.pattern, value)
                if metadata_match:
                    for metadata_value in auto_prop.value:
                        for index, gm_value in enumerate(metadata_match.groups()):
                            metadata_value = metadata_value.replace(f"${index+1}", gm_value)
                        default_metadata.update(json.loads(metadata_value))

            # Set API and Submission quotas
            elif auto_prop.type in ['api_quota', 'api_daily_quota', 'submission_quota',
                                    'submission_async_quota', 'submission_daily_quota']:
                if re.match(auto_prop.pattern, value):
                    quotas[auto_prop.type] = int(auto_prop.value[0])

    return access, user_type, roles, organization, groups, remove_roles, quotas, Classification.max_classification(classification, default_classification), default_metadata
