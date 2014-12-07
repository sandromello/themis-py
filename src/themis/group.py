"""
.. module:: themis
   :platform: Unix
   :synopsis: A minimum rate limiter for postfix. Write your own rules

.. moduleauthor:: Sandro Mello <sandromll@gmail.com>


"""
from themis.utils import isvalidtype, is_valid_redis_key
from netaddr import IPNetwork

class GroupError(Exception): pass

class Groups(object):
  def __init__(self, redis):
    self.redis = redis
    # Config DB => 1
    self.group_namespace = 'group'

  def namespace(self, group_name):
    return ':'.join((self.group_namespace, group_name))

  def get_all_group_members(self):
    """
    Get all group members 
    Returns a dict: {'group:group_name' : ['record01', 'record02', ...], ...}
    """
    groups = {}
    for group in self.get_all_groups():
      group_name = group.split(':')[1]
      groups[group_name] = list(self.redis.smembers(group))
    if not groups:
      raise ValueError('There is any group stored')
    return groups

  def get_all_groups(self):
    """ 
    Get all keys starting with the string 'group:'
    Return a list
    """
    # TODO: Test it
    return list(self.redis.smembers('list:groups'))

  def setgroup(self, group_name, members):
    """
    Set a new group with the specified members. If the group exists it will append to it
    group_name - group_name of the group (str)
    members - members to add: @domain.com, account@, account@domain.com, a.b.c.d, a.b.c.d/cidr
    """
    is_valid_redis_key(group_name)
    if 'all' in group_name:
      raise ValueError('Choose another group name, reserverd word: "all"')

    group_name = group_name.lower()
    try:
      self.getgroup(group_name)
    except ValueError:
      # If does not exists, move to the next step
      pass
    else:
      raise GroupError('Group already exists')

    if type(members) is not list:
      raise TypeError('Expect a list. Found: %s' % type(members))

    if 'any' in members:
      raise ValueError('Wrong member identified, reserverd word: "any"')
    
    for member in members:
      data = isvalidtype(member)
      if type(data) is IPNetwork:
        members.remove(member)
        members.append(str(data))

    key = ':'.join((self.group_namespace, group_name))
    with self.redis.pipeline() as pipe:
      pipe.sadd(key, *members)
      pipe.sadd(':'.join(('list', 'groups')), key)
      pipe.execute()

  def editgroup(self, group_name, members):
    """
    Edit a group only if it exists and replace and add with the new values.
    group_name - group_name of the group (str)
    members - members to add: @domain.com, account@, account@domain.com, a.b.c.d, a.b.c.d/cidr
    """
    is_valid_redis_key(group_name)
    group_name = group_name.lower()
    if not self.getgroup(group_name):
      raise GroupError('Group "%s" does not exists' % group_name)
    if type(members) is not list:
      raise TypeError('Expect a list. Found: %s' % type(members))

    for member in members:
      data = isvalidtype(member)
      if type(data) is IPNetwork:
        members.remove(member)
        members.append(str(data))

    if 'any' in members:
      raise ValueError('Could not add "any" type members')

    key = self.namespace(group_name)
    with self.redis.pipeline() as pipe:
      pipe.sadd(key, *members)
      pipe.sadd(':'.join(('list', 'groups')), key)
      pipe.execute()

  def getgroup(self, group_name):
    """
    Get specified group members
    group_name - The group_name of the group
    """
    if group_name == 'any':
      return list('any')
    group = self.redis.smembers(self.namespace(group_name))
    if not group:
      raise ValueError('Could not find group by the name: ' + group_name)
    return list(group)

  def hasmember(self, group_name, members, invert=False):
    result = []
    for member in members:
      result.append(self.redis.sismember(self.namespace(group_name), member))
    if invert:
      return not True in result
    return True in result

  def delgroup(self, group_name):
    is_valid_redis_key(group_name)
    group = self.namespace(group_name)
    with self.redis.pipeline() as pipe:
      pipe.delete(group)
      pipe.srem('list:groups', group)
      del_result, _ = pipe.execute()
    if not del_result:
      raise GroupError('Group "%s" does not exists' % group_name)

  def delgroup_member(self, group_name, members):
    is_valid_redis_key(group_name)
    if type(members) is not list:
      raise TypeError('Expect a list. Found: %s' % type(members))

    replaced_members = self.getgroup(group_name)
    [replaced_members.remove(del_member) for del_member in members if del_member in replaced_members]
    if not replaced_members:
      raise GroupError('There only one member left. Remove group instead.')
    self.delgroup(group_name)
    self.setgroup(group_name, replaced_members)

  # TODO: Revisar that fuck!
  def scan(self, pattern):
    scan_list = []
    index = 0
    while True:
      index, items = self.redis.scan(index, pattern)
      scan_list += items
      if index == 0:
        break
    return scan_list