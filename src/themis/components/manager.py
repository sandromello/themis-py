import re
from netaddr import IPNetwork
from .exceptions import ItemNotFound, InconsistencyError
from .redismodels import (
  Policy, MetaData, ActionHeader, Group, 
  Pool, JAILBY_VALUES, JAILACTION_VALUES,
  POLICY_TYPES, RESERVED_NAMES
)

class Manager(object):
  def __init__(self, redishost='localhost', redisport=6379, redisdb=0, redispass=None):
    pass

  def create_policy(self, policy_name, enable=True, type='regular', priority=5.0, source='any',
    destination='any', jailby='Sender+', jailaction='monitor', jailspec='0:0', pool=None,
    replydata='', countrcpt=False, stophere=False, spf=False, onlyheaders=False, actionheaders=[]):
    """ Create a new policy into database
    """
    source_obj = Group.objects.filter(namespace = source).first()
    destination_obj = Group.objects.filter(namespace = source).first()
    if not source_obj and destination_obj:
      raise ValueError('Source %s or destination %s group not found' % (source, destination))
    policy = Policy(
      namespace = policy_name,
      enable = enable,
      type = type,
      priority = priority,
      source = source_obj,
      destination = destination_obj,
      jailby = jailby,
      jailaction = jailaction,
      jailspec = jailspec,
      replydata = replydata,
      countrcpt = countrcpt,
      stophere = stophere,
      spf = spf,
      onlyheaders = onlyheaders
    )
    # Append a pool if exists
    if pool:
      pool_obj = Pool.objects.filter(namespace = pool).first()
      if not pool_obj:
        raise ItemNotFound('Pool "%s" not found' % pool)
      policy.pool = pool_obj

    # Append action headers if exists
    ach = list()
    for h in actionheaders:
      header = ActionHeaders.objects.filter(namespace = h).first()
      if not header:
        raise ItemNotFound('Could not find action header "%s"' % h)
      ach.append(header)
    if ach:
      policy.actionheaders = ach

    policy.save()

  def modify_policy(self):
    """ Change a specific attribute from a policy
    """
    pass

  def delete_policy(self):
    """ Delete a specific policy
    """
    pass

  def create_pool(self, pool_name, servers):
    """ Create a new pool into database
    :param pool_name: The name of the pool
    :param servers: A list of servers to add into the pool
    """
    pool = Pool(
      namespace = pool_name,
      servers = servers
    )
    return pool.save()

  def modify_pool(self, pool_name, servers, remove=False):
    """ Modify the servers from a specific pool
    :param pool_name: The pool name
    :param remove: If it's True will remove the servers from the pool
    :param servers: A list of servers will be appended to the pool if remove parameter is False
    """
    pool = Pool.objects.filter(namespace = pool_name).first()
    if not pool:
      raise ItemNotFound('Pool "%s" not found' % pool_name)
    # From unicode to str
    servers = [str(server) for server in servers]
  
    if remove:
      for srv in servers:
        if pool.servers == 1:
          raise InconsistencyError('Could not remove more servers, only ONE left')
        pool.servers.remove(srv)
      servers = pool.servers
      pool.delete()
      Pool(namespace = pool_name, servers = servers).save()
    else:
      servers = pool.servers + list(set(servers))
      pool.delete()
      Pool(namespace = pool_name, servers = servers).save()

  def delete_pool(self, pool_name):
    """ Delete an entire pool
    :param pool_name: The name of the pool
    """
    # TODO: Check if it's in USE by a policy
    pool = Pool.objects.filter(namespace = pool_name).first()
    if not pool:
      raise ItemNotFound('Could not find pool "%s"' % pool_name)
    policies = Policy.objects.filter(pool_id = pool.id)
    if policies:
      raise InconsistencyError('Could not remove a pool associate with policies: %s' % ', '.join(policies))
    pool.delete()

  def create_group(self, group_name, objects):
    """ Create a new group with objects
    :param group_name: The name of the group
    :param objects: The list of the objects
    """
    for obj in objects:
      self.isvalidtype(obj)
    group = Group(
      namespace = group_name,
      items = list(set(objects))
    )
    group.save()

  def delete_group(self, group_name):
    """ Delete a group
    :param group_name: The name of the group
    """
    group = Group.objects.filter(namespace = group_name).first()
    if not group:
      raise ItemNotFound('Could not find group "%s"' % group_name)
    policies = Policy.objects.filter(group_id = group.id)
    if policies:
      raise InconsistencyError('Could not remove a group associate with policies: %s' % ', '.join(policies))
    group.delete()

  def get_groups(self, group_name):
    return self._get_groups(group_name, indent=None)


  def _get_groups(self, group_name, indent=None):
    """ Get groups 
    :param group_name: The name of the group
    """
    if group_name == 'all':
      result = Group.objects.all()
    else:
      result = Group.objects.filter(namespace = group_name).first()
      if result:
        result = [result]

    if not result:
      return

    result = [g.asdict for g in result]
    if indent:
      return json.dumps(result, indent=2)
    elif indent == None:
      return json.dumps(result)
    
    #return result

  def modify_group(self, group_name, objects, remove=False):
    """ Modify the objects of a specific group
    :param group_name: The name of the group
    :param objects: The list of objects to modify
    :param remove: If True will remove the objects from the group, otherwise will append
    """
    pass

  def create_actionheader(self, name, lookupheader, regexp, newheader, newheader_value):
    """ Create a new action header rule
    :param name: The name of the rule
    :param lookupheader: Match this header in the milter session
    :param regexp: Use regexp to match the value
    :param newheader: The new header to add based on the match of lookupheader/regexp
    :param newheader_value: The new header value to add based on the match of lookupheader/regexp
    """
    pass

  def mod_actionheader(self, name, lookupheader=None, regexp=None, newheader=None, newheader_value=None):
    """ Modify an action header rule
    """
    pass

  def delete_actionheader(self, name):
    """ Delete a action header rule 
    """
    # TODO: Check if it's in USE by a policy
    pass

  def create_metadata(self, metadata_namespace, **metadata_keys):
    """ Add a metadata key into database
    :param metadata_namespace: The name of the metadata key
    :metadata_keys: The key/value parameters
    """
    pass

  def del_metadata(self, metadata_namespace):
    """ Delete a metadata key
    :param metadata_namespace: The name of the metadata key
    """
    pass

  def mod_metadata(self, metadata_namespace, **metadata_keys):
    """ Modify a metadata key
    :param metadata_namespace: The name of the metadata key
    :metadata_keys: The key/value parameters
    """
    pass

  @classmethod
  def isvalidtype(cls, data):
    # Match @anything. Domains
    if re.match(r'^@[\w\.]+$', data):
      return 'domain'
    # Match account@domain. Full mailnames
    elif re.match(r'[\w\.]+@[\w\.]+$', data):
      return 'fullmailname'
    elif data == 'any':
      return 'any'
    else:
      try:
        return IPNetwork(data)
      except Exception:
        raise ValueError('Cannot match any type for: %s' % data)