# File: cbdefense_connector.py
# Copyright (c) 2018-2021 Splunk Inc.
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
import time
import json
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))

#todo -- add the exception handling for exception

class CarbonBlackDefenseConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(CarbonBlackDefenseConnector, self).__init__()

        self._state = None
        self._base_url = None
        self._api_auth = None
        self._siem_auth = None
        self._custom_api_auth = None
        self._org_key = None

    def initialize(self):

        self._state = self.load_state()

        config = self.get_config()

        self._base_url = config['api_url'].strip('/')

        if 'api_key' in config and 'api_connector_id' in config:
            self._api_auth = '{0}/{1}'.format(config['api_key'], config['api_connector_id'])
        if 'siem_key' in config and 'siem_connector_id' in config:
            self._siem_auth = '{0}/{1}'.format(config['siem_key'], config['siem_connector_id'])
        if 'custom_api_key' in config and 'custom_api_connector_id' in config:
            self._custom_api_auth = '{0}/{1}'.format(config['custom_api_key'], config['custom_api_connector_id'])
        if 'org_key' in config:
            self._org_key = config.get('org_key')

        return phantom.APP_SUCCESS

    def finalize(self):

        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200 or response.status_code == 204:
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

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get", is_new_api=False):

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
        elif is_new_api:
            if not self._custom_api_auth:
                return RetVal(action_result.set_status(phantom.APP_ERROR, "The asset configuration parameters custom_api_key and custom_api_connector_id are "
                                                                          "required to run this action."))
            auth_header = {'X-Auth-Token': self._custom_api_auth}
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

        list_devices_api = "/appservices/v6/orgs/{0}/devices/_search".format(self._org_key)
        ret_val, response = self._make_rest_call(list_devices_api, action_result, data=params, method="post", is_new_api=True)

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
        # todo optimize below params

        body = {
            "action_type": "UPDATE_POLICY",
            "device_id": [param['device_id']],
            "options": {
                'policy_id': param['policy_id']
            }
        }

        update_policy_api = "/appservices/v6/orgs/{0}/device_actions".format(self._org_key)
        ret_val, response = self._make_rest_call(update_policy_api, action_result, data=body, method='post', is_new_api=True)

        if phantom.is_fail(ret_val):
            return ret_val
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully updated device's policy")

    def _handle_list_processes(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}
        query = ""
        result_params = {}
        if 'ip' in param:
            query += "(device_external_ip:{0} OR device_internal_ip:{0})".format(param['ip'])
        if 'host_name' in param:
            query_added = "device_name:{0}".format(param['host_name'])
            if query:
                query += " AND " + query_added
            else:
                query += query_added
        if 'owner' in param:
            query_added = "device_installed_by:{0}".format(param['owner'])
            if query:
                query += " AND " + query_added
            else:
                query += query_added
        if 'start' in param:
            result_params["start"] = params['start'] = param['start']
        if 'limit' in param:
            result_params["rows"] = params['rows'] = param['limit']
        if 'search_span' in param:
            search_span_val = param['search_span']
            if 'one day' in search_span_val or 'one week' in search_span_val or 'two weeks' in search_span_val or 'one month' in search_span_val:
                span_map = {'one day': '-1d', 'one week': '-1w', 'two weeks': '-2w', 'one month': '-1m'}
                search_span_val = span_map[search_span_val]
            else:
                search_span_val = "-" + search_span_val

            params['time_range'] = {
                "window": search_span_val
            }

        if not query:
            self.debug_print("No Mandatory Field selected")
            return action_result.set_status(phantom.APP_ERROR, "Add atleast value in one of following fields: ip, host name, owner")

        params["query"] = query

        #todo --imp
        # return error if user doesnot provide any one of the required parameter.
        # todo - steps
        # prepare the json data to be send with the api call.
        # first make the api call to get the job id.
        # then make the call to get the results for that job_id
        # the result json returned by the 2nd step will be used for showing info to the user.

        # process_query = {
        #     "query": "enriched_event_type:SYSTEM_API_CALL"
        # }
        self.debug_print("sahils--- \n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n{0}".format(params))
        get_job_id_api = "/api/investigate/v2/orgs/{0}/processes/search_jobs".format(self._org_key)
        ret_val, resp_json_job_id = self._make_rest_call(get_job_id_api, action_result, data=params, method="post", is_new_api=True)

        self.debug_print("sahil res_json_data \n\n\n\n\n\n\n{0}".format(resp_json_job_id))

        if phantom.is_fail(ret_val):
            return ret_val
        job_id = resp_json_job_id.get("job_id")

        job_info_api = "/api/investigate/v1/orgs/{0}/processes/search_jobs/{1}".format(self._org_key, job_id)
        ret_val, job_info = self._make_rest_call(job_info_api, action_result, is_new_api=True)
        if phantom.is_fail(ret_val):
            return ret_val
        completed = job_info.get("completed")
        contacted = job_info.get("contacted")

        #todo try to optimize the below logic
        if completed != contacted:
            # if it is not equal then update the user with a proper message to retry after sometime.
            # todo no need to add sleep or re-try the api call.
            message = "process still not completed so results may vary. please re-try after sometime."

        get_result_api = "/api/investigate/v2/orgs/{0}/processes/search_jobs/{1}/results".format(self._org_key, job_id)
        ret_val, resp_json = self._make_rest_call(get_result_api, action_result, params=result_params, is_new_api=True)

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
        query = ""

        if 'ip' in param:
            query += "(device_external_ip:{0} OR device_internal_ip:{0})".format(param['ip'])
        if 'host_name' in param:
            query_added = "device_name:{0}".format(param['host_name'])
            if query:
                query += " AND " + query_added
            else:
                query += query_added
        if 'owner' in param:
            query_added = "device_installed_by:{0}".format(param['owner'])
            if query:
                query += " AND " + query_added
            else:
                query += query_added
        if 'application' in param:
             query_added = "process_original_filename:{0}".format(param['application'])
             if query:
                 query += " AND " + query_added
             else:
                 query += query_added
        if 'event_type' in param:
             query_added = "enriched_event_type:{0}".format(param['event_type'])
             if query:
                query += " AND " + query_added
             else:
                query += query_added
        if 'hash' in param:
            query_added = "process_hash:{0}".format(param['hash'])
            if query:
                query += " AND " + query_added
            else:
                query += query_added
        if 'search_span' in param:
            search_span_val = param['search_span']
            if 'one day' in search_span_val or 'one week' in search_span_val or 'two weeks' in search_span_val:
                span_map = {'one day': '-1d', 'one week': '-1w', 'two weeks': '-2w'}
                search_span_val = span_map[search_span_val]
            else:
                search_span_val = "-" + search_span_val

            params['time_range'] = {
                "window": search_span_val
            }

        if not query:
            self.debug_print("No Mandatory Field selected")
            return action_result.set_status(phantom.APP_ERROR, "Add atleast value in one of following fields: event_type, ip, host name, hash, application, owner")

        params["query"] = query
        self.debug_print("query parameters are", format(params))

        ret_val, resp_json = self._make_rest_call('/api/investigate/v2/orgs/{0}/enriched_events/search_jobs'.format(self._org_key),action_result, data=params,method='post', is_new_api=True)
        self.debug_print('Response Body for ListEvent Action', resp_json.get("job_id"))

        if not resp_json.get("job_id"):
            self.debug_print("Response String for Event Search Status failed")
        else:
            resp_json_search_result_data=self.retry_search_event(resp_json.get("job_id"),action_result,"search_jobs");
            self.debug_print("*****resp_json_search_result_data",resp_json_search_result_data)

        if phantom.is_fail(ret_val):
            return ret_val

        results = resp_json_search_result_data.get('results', [])

        if results:
            for result in results:
                action_result.add_data(result)

            summary = action_result.update_summary({})
            summary['num_results'] = len(results)

            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            self.debug_print("No Record Found")
            return action_result.set_status(phantom.APP_SUCCESS, "No records found")

    def retry_search_event(self,job_id,action_result,job_name):
        self.save_progress("In retry_search_event for: {0}".format(self.get_action_identifier()))
        max_retry = 3
        retries = 0
        i=0
        for i in range(2):
            try:
                self.debug_print("while retrying $$$$")
                if job_name == "search_jobs":
                    ret_val_search_event, resp_json_search_event = self._make_rest_call('/api/investigate/v1/orgs/{1}/enriched_events/{2}/{0}'.format(job_id,self._org_key,job_name), action_result, is_new_api=True)
                    self.debug_print("Response String for Event for completed Search Status",resp_json_search_event.get("completed"))
                    self.debug_print("Response String for Event for contactedSearch Status",resp_json_search_event.get("contacted"))
                elif job_name == "detail_jobs":
                    ret_val_search_event, resp_json_search_event = self._make_rest_call('/api/investigate/v2/orgs/{1}/enriched_events/{2}/{0}'.format(job_id, self._org_key, job_name),action_result, is_new_api=True)
                    self.debug_print("Response String for Event for completed Search Status",resp_json_search_event.get("completed"))
                    self.debug_print("Response String for Event for contactedSearch Status",resp_json_search_event.get("contacted"))

                if resp_json_search_event.get("completed") ^ resp_json_search_event.get("contacted"):
                    self.debug_print("Completed and Contacted events are not verified")
                    retries += 1
                    if retries <= max_retry:
                        self.debug_print("Retrying ... #%s", retries)
                        time.sleep(5)
                        continue
                    else:
                        break
                else:
                    break
            except Exception as e:
                self.debug_print("Exception Occured")
                break

        self.debug_print("Before calling result")
        ret_val_search_result, resp_json_search_result = self._make_rest_call('/api/investigate/v2/orgs/{1}/enriched_events/{2}/{0}/results'.format(job_id,self._org_key,job_name), action_result,is_new_api=True )
        self.debug_print("resp_json_search_result", resp_json_search_result)
        return resp_json_search_result

    def _handle_get_event(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        params = {}
        my_list = list(filter(None, param['id'].split(",")))
        params["event_ids"] = my_list
        self.debug_print("query parameters for getEvent are", format(params))

        ret_val, resp_json = self._make_rest_call('/api/investigate/v2/orgs/{0}/enriched_events/detail_jobs'.format(self._org_key), action_result,
            data=params, method='post',is_new_api=True)
        self.debug_print('Response Body for GetEvent Action', resp_json.get("job_id"))

        if not resp_json.get("job_id"):
            self.debug_print("Response String for Get Event Search Status failed")
        else:
            resp_json_search_result_data = self.retry_search_event(resp_json.get("job_id"), action_result,"detail_jobs");
            self.debug_print("get event resp_json_search_result_data", resp_json_search_result_data)

        if phantom.is_fail(ret_val):
            return ret_val

        if resp_json_search_result_data.get('results'):
            for result in resp_json_search_result_data.get('results'):
                action_result.add_data(result)

            summary = action_result.update_summary({})
            summary['num_results'] = len(resp_json_search_result_data.get('results'))
            return action_result.set_status(phantom.APP_SUCCESS,"Successfully retrieved event data")
        else:
            self.debug_print("No Record Found")
            return action_result.set_status(phantom.APP_SUCCESS, "No records found")

    def _handle_get_alert(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, resp_json = self._make_rest_call('/appservices/v6/orgs/{1}/alerts/{0}'.format(param['id'],self._org_key), action_result, is_new_api=True)

        self.debug_print("Response String for getAlert", resp_json)

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(resp_json)
        summary = action_result.set_summary({})
        summary['device'] = resp_json.get('device_name', 'UNKNOWN')

        #summary['device'] = resp_json.get('deviceInfo', {}).get('deviceName', 'UNKNOWN')
        #summary['num_events'] = len(resp_json.get('events', []))

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
