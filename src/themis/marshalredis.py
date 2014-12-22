from themis.static import METADATA_CUSTOM_CALLBACK, POLICY_CUSTOM_CALLBACK, FEATURES_CUSTOM_CALLBACK
from redis import StrictRedis
from redis.client import BasePipeline
from itertools import izip
from ast import literal_eval
import marshal

MARSHAL_TYPES = [list, dict, bool]

class MarshalRedis(StrictRedis):
  def hmset(self, name, mapping, mapping_types=None):
    if mapping_types:
      for key, type_info in mapping_types.items():
        if key in mapping and type_info in MARSHAL_TYPES:
            mapping[key] = marshal.dumps(mapping[key])
    return super(MarshalRedis, self).hmset(name, mapping)

  def hset(self, name, key, value, feat_mapping=False):
    custom_callbacks = dict(FEATURES_CUSTOM_CALLBACK.items() + METADATA_CUSTOM_CALLBACK.items())
    if feat_mapping:
      try:
        if custom_callbacks[key] in MARSHAL_TYPES:
          if value.lower().title() in ['True', 'False']:
            value = value.lower().title()
          value = marshal.dumps(literal_eval(value))
        else:
          value = custom_callbacks[key](value)
      except Exception, e:
        raise ValueError('Wrong type found: %s Exception: %s' % (value, e))
    return super(MarshalRedis, self).hset(name, key, value)

  def hgetall(self, name, callbacks=None):
    response = super(MarshalRedis, self).hgetall(name)
    if not callbacks:
      callbacks = dict(METADATA_CUSTOM_CALLBACK.items() + FEATURES_CUSTOM_CALLBACK.items() + POLICY_CUSTOM_CALLBACK.items())
    return self.pairs_to_dict_typed(response, callbacks) or {}

  def pipeline(self, transaction=True, shard_hint=None):
    return MarshalStrictPipeline(
      self.connection_pool,
      self.response_callbacks,
      transaction,
      shard_hint
    )

  def zrange(self, name, start, end, desc=False, withscores=False, score_cast_func=float, as_list_of_tuples=False):
    response = super(MarshalRedis, self).zrange(name, start, end, desc, withscores, score_cast_func)
    if not as_list_of_tuples:
      return response
      
    if not response or not withscores:
      return response
    response = map(int, response)
    it = iter(response)
    list_of_tuples = sorted(list(izip(it, it)))
    return zip(*list_of_tuples)

  def pairs_to_dict_typed(self, response, type_info):
    result = {}
    for key, value in response.items():
      if key in type_info:
        try:
          if type_info[key] in MARSHAL_TYPES:
            value = marshal.loads(value)
          else:
            value = type_info[key](value)
        except Exception:
          # if for some reason the value can't be coerced, just use
          # the string value
          pass
      result[key] = value
    return result

# Pipeline must overrided methods
class MarshalStrictPipeline(BasePipeline, MarshalRedis): pass