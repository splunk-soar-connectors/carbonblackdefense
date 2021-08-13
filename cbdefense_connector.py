# --
# File: cbdefense_connector.py
#
# Copyright (c) 2018-2020 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from carbonblackdefense_consts import *
import requests
import json
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class CarbonBlackDefenseConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(CarbonBlackDefenseConnector, self).__init__()

        self._state = None
        self._base_url = None
        self._api_auth = None
        self._siem_auth = None
        self._org_key = None

    def initialize(self):

        self._state = self.load_state()

        config = self.get_config()

        self._base_url = config['api_url'].strip('/')
        self._org_key = "434523gerty"
        if 'api_key' in config and 'api_connector_id' in config:
            self._api_auth = '{0}/{1}'.format(config['api_key'], config['api_connector_id'])
        if 'siem_key' in config and 'siem_connector_id' in config:
            self._siem_auth = '{0}/{1}'.format(config['siem_key'], config['siem_connector_id'])

        return phantom.APP_SUCCESS

    def finalize(self):

        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        if 'message' in resp_json:
            message = resp_json['message']
        else:
            message = "Error from server. Status Code: {0} Data from server: {1}".format(
                    r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML resonse, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get"):

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        if 'notification' in endpoint:
            if not self._siem_auth:
                return RetVal(action_result.set_status(phantom.APP_ERROR, "The asset configuration parameters siem_key and siem_connector_id are required to run this action."))
            auth_header = {'X-Auth-Token': self._siem_auth}
        else:
            if not self._api_auth:
                return RetVal(action_result.set_status(phantom.APP_ERROR, "The asset configuration parameters api_key and api_connector_id are required to run this action."))
            auth_header = {'X-Auth-Token': self._api_auth}

        if headers:
            headers.update(auth_header)
        else:
            headers = auth_header

        try:
            r = request_func(
                            url,
                            json=data,
                            headers=headers,
                            verify=config.get('verify_server_cert', False),
                            params=params)
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Querying policies to test connectivity")

        ret_val, response = self._make_rest_call('/integrationServices/v3/policy', action_result)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return ret_val

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_policies(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, response = self._make_rest_call('/integrationServices/v3/policy', action_result)

        if phantom.is_fail(ret_val):
            return ret_val

        results = response.get('results', [])

        for result in results:
            action_result.add_data(result)

        action_result.set_summary({'num_policies': len(results)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_policy(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        body = {
                "policyInfo": {
                    "name": param['name'],
                    "description": param['description'],
                    "priorityLevel": param['priority'],
                    "version": 2  # This is required to be 2 by the API
                }
            }

        if 'json_fields' in param:
            try:
                policy_info = json.loads(param['json_fields'])
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Could not parse JSON from 'json_fields' parameter: {0}".format(e))
            body['policy'] = policy_info

        ret_val, response = self._make_rest_call('/integrationServices/v3/policy', action_result, data=body, method='post')

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response)
        action_result.set_summary({'policy_id': response.get('policyId', 'UNKNOWN')})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_policy(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, response = self._make_rest_call('/integrationServices/v3/policy/{0}'.format(param['id']), action_result, method='delete')

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Policy successfully deleted")

    def _handle_add_rule(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            rule_info = json.loads(param['rules'])
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Could not parse JSON from rules parameter: {0}".format(e))

        body = {"ruleInfo": rule_info}

        ret_val, response = self._make_rest_call('/integrationServices/v3/policy/{0}/rule'.format(param['id']), action_result, data=body, method='post')

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response)
        action_result.set_summary({'rule_id': response.get('ruleId', 'UNKNOWN')})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_rule(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, response = self._make_rest_call('/integrationServices/v3/policy/{0}/rule/{1}'.format(param['policy_id'], param['rule_id']), action_result, method='delete')

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Rule successfully deleted")

    def _handle_list_devices(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}
        if 'start' in param:
            params['start'] = param['start']
        if 'limit' in param:
            params['rows'] = param['limit']

        ret_val, response = self._make_rest_call('/integrationServices/v3/device', action_result, params=params)

        if phantom.is_fail(ret_val):
            return ret_val

        results = response.get('results', [])

        for result in results:
            action_result.add_data(result)

        action_result.set_summary({'num_devices': len(results)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_device(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        body = {'policyId': param['policy_id']}

        ret_val, response = self._make_rest_call('/integrationServices/v3/device/{0}'.format(param['device_id']), action_result, data=body, method='patch')

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully updated device's policy")

    def _handle_list_processes(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        if 'ip' in param:
            params['ipAddress'] = param['ip']
        if 'host_name' in param:
            params['hostName'] = param['host_name']
        if 'owner' in param:
            params['ownerName'] = param['owner']
        if 'start' in param:
            params['start'] = param['start']
        if 'limit' in param:
            params['rows'] = param['limit']
        if 'search_span' in param:
            span_map = {'one day': '1d', 'one week': '1w', 'two weeks': '2w', 'one month': '1m'}
            params['searchWindow'] = span_map[param['search_span']]

        ret_val, resp_json = self._make_rest_call('/integrationServices/v3/process', action_result, params=params)

        if phantom.is_fail(ret_val):
            return ret_val

        results = resp_json.get('results', [])

        for result in results:
            action_result.add_data(result)

        summary = action_result.update_summary({})
        summary['num_results'] = len(results)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_events(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        if 'ip' in param:
            params['ipAddress'] = param['ip']
        if 'host_name' in param:
            params['hostName'] = param['host_name']
        if 'hash' in param:
            params['sha256Hash'] = param['hash']
        if 'application' in param:
            params['applicationName'] = param['application']
        if 'owner' in param:
            params['ownerName'] = param['owner']
        if 'event_type' in param:
            params['eventType'] = param['event_type']
        if 'search_span' in param:
            span_map = {'one day': '1d', 'one week': '1w', 'two weeks': '2w'}
            params['searchWindow'] = span_map[param['search_span']]

        ret_val, resp_json = self._make_rest_call('/integrationServices/v3/event', action_result, params=params)

        if phantom.is_fail(ret_val):
            return ret_val

        count = 0
        for result in resp_json.get('results', []):
            if 'description' in param:
                if param['description'] in result['longDescription']:
                    action_result.add_data(result)
                    count += 1
            else:
                action_result.add_data(result)
                count += 1

        summary = action_result.update_summary({})
        summary['num_results'] = count

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_event(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, resp_json = self._make_rest_call('/integrationServices/v3/event/{0}'.format(param['id']), action_result)

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(resp_json)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved event data")

    def _handle_get_alert(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, resp_json = self._make_rest_call('/integrationServices/v3/alert/{0}'.format(param['id']), action_result)

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(resp_json)

        summary = action_result.set_summary({})
        summary['device'] = resp_json.get('deviceInfo', {}).get('deviceName', 'UNKNOWN')
        summary['num_events'] = len(resp_json.get('events', []))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_notifications(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, resp_json = self._make_rest_call('/integrationServices/v3/notification', action_result)

        if phantom.is_fail(ret_val):
            return ret_val

        notifications = resp_json.get('notifications', [])

        for notification in notifications:
            action_result.add_data(notification)

        action_result.set_summary({'num_notifications': len(notifications)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_policy(self, param):

        action_result = self.add_action_result(ActionResult(param))
        policy_id = param["policy_id"]
        endpoint = "/integrationServices/v3/policy/" + str(policy_id)

        try:
            data = json.loads(param["policy"])
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Policy needs to be valid JSON data: " + str(e))

        if "policyInfo" not in data:
            data = {"policyInfo": data}

        if "id" not in data.get("policyInfo", {}):
            data["policyInfo"]["id"] = policy_id

        ret_val, response = self._make_rest_call(endpoint, action_result, data=data, method="put")

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Policy updated successfully")

    def _handle_get_policy(self, param):

        action_result = self.add_action_result(ActionResult(param))
        policy_id = param["policy_id"]
        endpoint = "/integrationServices/v3/policy/" + str(policy_id)
        ret_val, response = self._make_rest_call(endpoint, action_result)

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR,
                                            'Error retrieving policy: {0}'
                                            .format(response))
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Policy retrieved successfully")

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)
        elif action_id == 'get_notifications':
            ret_val = self._handle_get_notifications(param)
        elif action_id == 'list_processes':
            ret_val = self._handle_list_processes(param)
        elif action_id == 'list_policies':
            ret_val = self._handle_list_policies(param)
        elif action_id == 'create_policy':
            ret_val = self._handle_create_policy(param)
        elif action_id == 'delete_policy':
            ret_val = self._handle_delete_policy(param)
        elif action_id == 'update_device':
            ret_val = self._handle_update_device(param)
        elif action_id == 'list_devices':
            ret_val = self._handle_list_devices(param)
        elif action_id == 'list_events':
            ret_val = self._handle_list_events(param)
        elif action_id == 'delete_rule':
            ret_val = self._handle_delete_rule(param)
        elif action_id == 'get_event':
            ret_val = self._handle_get_event(param)
        elif action_id == 'get_alert':
            ret_val = self._handle_get_alert(param)
        elif action_id == 'add_rule':
            ret_val = self._handle_add_rule(param)
        elif action_id == 'get_policy':
            ret_val = self._handle_get_policy(param)
        elif action_id == 'update_policy':
            ret_val = self._handle_update_policy(param)

        return ret_val


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print("Accessing the Login page")
            login_url = BaseConnector._get_phantom_base_url() + '/login'
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CarbonBlackDefenseConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
