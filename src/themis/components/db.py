from .exceptions import PolicyError, ThemisException
from .redismodels import Policy, MetaData, Policy, ActionHeader, Group, Pool
from redisco import models
import json

class Process(object):
  def add_policy(self, policy_name):
    
