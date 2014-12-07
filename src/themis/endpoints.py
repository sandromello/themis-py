from utils import TMSException
from flask import Flask, request, jsonify, app, make_response, Response, json
from werkzeug.exceptions import default_exceptions
from werkzeug.exceptions import HTTPException
from utils import Credentials, TMSException
from traceback import format_exc
from functools import wraps
import yaml, sys, logging.config, redis, socket

from policy import Policy, PolicyData
from group import Groups
from AI import AI

__all__ = ['make_json_app']

REQUIRED_POLICY_PARAMS = ['Source', 'Destination', 'JailSpec']
DEFAULT_POLICY_PARAMS = {
  'enable' : 'TRUE',
  'type' : 'regular',
  'priority' : 5,
  'jailby' : 'Sender:user@domain+',
  'jailheader' : 'X-Themis-Quarantine',
  'jailaction' : 'monitor',
  'replydata' : 'Limit reached. Blocking for %s second(s)',
  'countsentprobation' : 1,
  'countrcpt' : 'FALSE',
  'stophere' : 'FALSE',
  'requestsmon' : 'FALSE',
  'subjectprobation' : 0.5,
  'ipprobation' : 0.5,
  'blockprobation' : 0.5,
  'countsentprobation' : 1
}

class DictToObject(object):
  """ Convert dict to object """
  def __init__(self, **entries):
    self.__dict__.update(entries)

def make_json_app(import_name, **kwargs):
  """
  Creates a JSON-oriented Flask app.

  All error responses that you don't specifically
  manage yourself will have application/json content
  type, and will contain JSON like this (just an example):

  { "message": "405: Method Not Allowed" }
  """
  def make_json_error(ex):
    response = jsonify(message=str(ex))
    response.status_code = (ex.code
                            if isinstance(ex, HTTPException)
                            else 500)
    return response

  app = Flask(import_name, **kwargs)
  for code in default_exceptions.iterkeys():
    app.error_handler_spec[None][code] = make_json_error

  return app

try:
  with open('/etc/themis/config.yaml') as f:
    config, _, logger_config = yaml.load_all(f)

  logging.config.dictConfig(logger_config['logger'])
  # Convert Dict to Objects: E.g.: config.property
  config = DictToObject(**config)
  logger = logging.getLogger('endpoints')
  auth = Credentials(redis.StrictRedis(config.redis_server))

  app = make_json_app(__name__)
  app.debug = True

except Exception, ex:
  print 'Error doing the initial config: %s\n%s' % (ex, format_exc())
  sys.exit(1)

def hgetall_custom_callback(response):
  data = dict(Policy.POLICY_CUSTOM_CALLBACK.items())
  return response and AI.pairs_to_dict_typed(response, data) or {}

####### ----------------- #######
####### RESPONSE HANDLERS #######
####### ----------------- #######

@app.errorhandler(TMSException)
def response_error(error):
  headers = error.headers
  headers['Content-Type'] = 'application/json'
  del error.__dict__['headers']
  return Response(json.dumps(error.__dict__), error.status_code, headers)
  
def response_success(message, status_code=200):
  headers = {'Content-Type' : 'application/json'}
  message = { 'message' : message, 'status_code' : status_code }
  return Response(json.dumps(message), status_code, headers)

####### ---------- #######
####### DECORATORS #######
####### ---------- #######

def validate_token(f):
  """ Decorated function to validate a given token based on server name """
  @wraps(f)
  def decorated(*args, **kwargs):
    request_token = request.headers.get('AUTHTOKEN')
    request_ipaddress = request.environ.get('REMOTE_ADDR')
    server_name = socket.getfqdn(request_ipaddress)
    logger.debug('Resolved: %s Hostname: %s Request Token: %s' % (request_ipaddress, server_name, request_token))
    
    if not request.headers.get('REDISHOST'):
      raise TMSException(message='Missing "REDISHOST" header', status_code=400)
    
    rd = redis.StrictRedis(request.headers.get('REDISHOST'), password=request.headers.get('REDISPASSWORD'))
    rd.set_response_callback('HGETALL', hgetall_custom_callback)
    
    try:
      if not request_token or not auth.is_valid_token(request_token, server_name):
        headers = { 'WWW-Authenticate' : 'Custom realm="themis"', 
        'Location' : request.url_root + 'generatetoken', 
        'Content-Type' : 'application/json' }
        raise TMSException(message='Could not find request token or secret key is invalid',
          status_code=401, headers=headers)
    except redis.exceptions.ConnectionError:
      raise TMSException(message='Error connecting to redis server %s' % kwargs['redis_server'], status_code=400)
    kwargs['rd'] = rd
    logger.info('Valid token found!')
    return f(*args, **kwargs)
  return decorated

def extract_body(f):
  """ Decorated function to extract the entity body of requests and also dealing with API response errors """
  @wraps(f)
  def decorated(*args, **kwargs):
    json_data = None
    if request.method in ['POST', 'PUT', 'DELETE']:
      try:
        json_data = request.json
      except Exception:
        logger.error('415 - Unsupported Media Type: %s' % request.data)
        raise TMSException(message='Could not extract json data', status_code=415)
    kwargs['json_data'] = json_data

    try:
      method = f(*args, **kwargs)
      return method
    except TMSException:
      raise
    except Exception, e:
      # TODO: CLEAN IT
      logger.exception(e)
      raise TMSException(message=e.message, status_code=400)
  return decorated

####### --------- #######
####### ENDPOINTS #######
####### --------- #######

@app.route('/generatetoken', methods=['POST'])
def generate_token():
  """ Generate a new token based on a SECRETKEY matching a server name. Read more in idnsgen CLI
  """
  request_secretkey = request.headers.get('SECRETKEY')
  logger.debug('SECRETKEY header: %s' % request_secretkey)
  if not request_secretkey:
    raise TMSException(message='Could not find SECRETKEY in header', status_code=401)

  request_ipaddress = request.environ.get('REMOTE_ADDR')
  server_name = socket.getfqdn(request_ipaddress)
  logger.debug('Resolved: %s Hostname: %s' % (request_ipaddress, server_name))
  if auth.is_valid_secretkey(request_secretkey, server_name):
    return response_success({'authtoken' : auth.gen_token(config.expiretoken)}, status_code=201)
  raise TMSException(message='Is not a valid secret key', status_code=403)

@app.route('/groups', methods=['GET'])
@validate_token
def groups(rd):
  return response_success(message=Groups(rd).get_all_group_members(), status_code=200)

@app.route('/group/<group_name>', methods=['POST', 'PUT', 'GET', 'DELETE'])
@extract_body
@validate_token
def group(rd, json_data, group_name):
  grp, response_data, response_status = [Groups(rd), 'OK', 200]
  if request.method == 'POST':
    grp.setgroup(group_name, json_data)
    response_data, response_status = ['CREATED', 201]
  elif request.method == 'PUT':
    grp.editgroup(group_name, json_data)
  elif request.method == 'DELETE':
    if not json_data:
      grp.delgroup(group_name)
    else:
      grp.delgroup_member(group_name, json_data)
  else:
    response_data = grp.getgroup(group_name)
  return response_success(message=response_data, status_code=response_status)

@app.route('/policy/<policy_name>', methods=['POST', 'PUT', 'GET', 'DELETE'])
@extract_body
@validate_token
def policy(rd, json_data, policy_name):
  """ Change a specific policy configuration """
  policy, response_status, response_data = [Policy(rd), 200, 'OK']

  if request.method in ['POST', 'PUT']:
    json_data['policy_name'] = policy_name

  if request.method == 'GET':
    response_data = policy.getpolicy(policy_name)
  elif request.method == 'PUT':
    policy.modifypolicy(json_data)
  elif request.method == 'POST':
    # Check to see if has all required params on the entity body
    if not len(REQUIRED_POLICY_PARAMS) == len(set(REQUIRED_POLICY_PARAMS) & set(json_data)):
      raise TMSException(message='Missing required values %s' % ', '.join(REQUIRED_POLICY_PARAMS), status_code=415)

    # Configure default values 
    for default_key, value in DEFAULT_POLICY_PARAMS.items():
      if default_key not in json_data:
        json_data[default_key] = value

    logger.debug('json_data: %s' % json_data)
    try:
      policy.setpolicy(PolicyData(**json_data))
    except Exception, e:
      logger.exception(e)
      raise TMSException(message='Error setting policy: %s' % e.message, status_code=400)
    response_data, response_status = ['CREATED', 201]
  elif request.method == 'DELETE':
    pdata = PolicyData(**json_data)
    try:
      policy.delete(policy_name)
    except ValueError:
      raise TMSException(message='Could not find policy %s' % policy_name, status_code=404)
  
  return response_success(message=response_data, status_code=response_status)

@app.route('/policies', methods=['GET', 'DELETE'])
@extract_body
@validate_token
def policies(rd, json_data, policy_name):
  policy = Policy(rd)
  response_data = {}
  if request.method == 'GET':
    policies = policy.get_all_policies()
    for policy_name in policies:
      pdata = policies[policy_name]
      response_data[policy_name] = pdata.as_dict
  else:
    deleted_policies = 0
    for policy_name in json_data['policies']:
      try:
        deleted_policies += 1
        policy.delete(policy_name)
      except KeyError:
        raise TMSException(message='Missing required name "policies"')
      except ValueError:
        deleted_policies -= 1
        continue
    response_data = 'Deleted %s policies' % deleted_policies
  return response_success(message=response_data)

@app.route('/pool/<pool_name>/poolserver/<pool_server>', methods=['DELETE'])
def pool_server(rd, json_data, pool_name, pool_server):
  deleted_servers = Policy(rd).remove_server_of_pool(pool_name, pool_server)
  return response_success(message='%s server(s) deleted' % deleted_servers)

@app.route('/pool/<pool_name>', methods=['GET', 'POST', 'DELETE'])
@extract_body
@validate_token
def pool(rd, json_data, pool_name):
  policy, response_data, response_status = [Policy(rd), None, 200]
  if request.method == 'POST':
    policy.addpool(pool_name, json_data['servers'])
    response_status = 201
  elif request.method == 'DELETE':
    policy.remove_pool(pool_name)
    response_status = 204
  else:
    response_data = policy.get_pool(pool_name)
    #policy.remove_pool_servers(pool_name, json_data['servers'])
  return response_success(message=response_data, status_code=response_status)

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8441)