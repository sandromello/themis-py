from datetime import datetime, timedelta
from numpy import polyfit
from math import ceil
from themis.static import FEATURES_CUSTOM_CALLBACK, METADATA_CUSTOM_CALLBACK
import time

class AI(object):
  def __init__(self, redis, tmetadata, ai_object):
    # TODO: DEFINE AN EXPIRATION FOR METADATA
    #self.namespace = config.get('ai_namespace') or 'AI'
    #self.bool = lambda b: b is True or b == 'True' or False
    # Global config MUST contain all the features keys, all the metadata necessary
    #self.global_config = config
    self.redis = redis
    self.ai_object = ai_object
    #metadata_namespace = ':'.join((self.namespace, 'metadata', ai_object))
    #self.redis.set_response_callback('HGETALL', self.hgetall_custom_callback)
    self.tmetadata = tmetadata
    self.build_namespaces(self.tmetadata.predictBy)
    
    #self.learningBlueMode = self.tmetadata.learningBlueMode or True
    #self.learningRedMode = self.bool(self.tmetadata.get('learningRedMode')) or False
    #self.learnTimeFrameValue = self.tmetadata.get('learnTimeFrameValue') or self.global_config['learnTimeFrameValue']
    #self.learnTimeFrameValue = map(int, self.learnTimeFrameValue.split(':'))

    if not self.redis.exists(self.tmetadata.namespace):
      # If there's any metadata, should not exist any data
      self.redis.delete(self.datablue_namespace, self.datared_namespace)

  def build_namespaces(self, predictBy):
    self.data_namespace = ':'.join((self.tmetadata.global_namespace, predictBy, 'data', self.ai_object))
    self.datablue_namespace = ':'.join((self.tmetadata.global_namespace, 'BLUE', 'data', self.ai_object))
    self.datared_namespace = ':'.join((self.tmetadata.global_namespace, 'RED', 'data', self.ai_object))
    self.metadata_namespace = ':'.join((self.tmetadata.global_namespace, 'metadata', self.ai_object))

  @classmethod
  def get_timeframe(self, time_frame_data, creation_date=None, custom_date=None):
    timeframe_minutes, days = time_frame_data
    # custom_date for testing 
    now = custom_date or datetime.now()
    if creation_date:
      # Divide the given time in minutes
      creation_date = datetime.fromtimestamp(float(creation_date))
      future = creation_date + timedelta(days=days)

      if now > future:
        # We stop learning because the time frame is over
        return False

    # Here we divide the days by minutes an then divide again to get the time frames of the days. 
    # So if a day has 1440 minutes and we divide by 2, we got 720 minutes, that way we can have time windows of 2 minutes
    now_in_minutes = (now.hour * (days * 60) + now.minute) / timeframe_minutes
    return now_in_minutes

  @classmethod
  def is_safe(cls, time_frame_data, total_slope_line_data, safe_value=30.0):
    # TODO: Check if is safe to predict, return the percentage based on the total records
    timeframe_minutes, days = time_frame_data
    total_points = 24 * (days * 60) / timeframe_minutes
    percentage = (total_slope_line_data * 100) / total_points
    return percentage >= safe_value
      
  def learnBlue(self, requests, custom_date=None):
    if not self.tmetadata.learningBlueMode:
      return

    timeframe_current_minutes = self.get_timeframe(self.tmetadata.learnTimeFrameValue, self.tmetadata.blue_creation_date, custom_date)
    if not timeframe_current_minutes:
      # We stop learning here
      self.tmetadata.learningBlueMode = False
      self.set_metadata()
    else:
      with self.redis.pipeline() as pipe:
        #print timeframe_current_minutes
        # The result of zincrby is how much was incremented
        pipe.zincrby(self.datablue_namespace, timeframe_current_minutes, requests)
        self.set_metadata(pipe)

  def learnRed(self, requests, custom_date=None):
    if not self.tmetadata.learningRedMode:
      return

    timeframe_current_minutes = self.get_timeframe(self.tmetadata.learnTimeFrameValue, self.tmetadata.red_creation_date, custom_date)
    if not timeframe_current_minutes:
      # We stop learning here
      self.tmetadata.learningRedMode = False
      self.set_metadata()
    else:
      with self.redis.pipeline() as pipe:
        # The result of zincrby is how much was incremented
        pipe.zincrby(self.datared_namespace, timeframe_current_minutes, requests)
        self.set_metadata(pipe)

  def set_metadata(self, pipe=None):
    self.tmetadata.last_update = time.time()
    if not pipe:
      with self.redis.pipeline() as p:
        p.hmset(self.tmetadata.namespace, self.tmetadata.as_dict, 
          dict(FEATURES_CUSTOM_CALLBACK.items() + METADATA_CUSTOM_CALLBACK.items()))
        p.expire(self.tmetadata.namespace, self.tmetadata.global_ttl)
        p.execute()
    else:
      if self.tmetadata.learningBlueMode and not self.tmetadata.blue_creation_date:
        self.tmetadata.blue_creation_date = time.time()
      elif self.tmetadata.learningRedMode and not self.tmetadata.red_creation_date:
        self.tmetadata.red_creation_date = time.time()

      pipe.hmset(self.tmetadata.namespace, self.tmetadata.as_dict, 
        dict(FEATURES_CUSTOM_CALLBACK.items() + METADATA_CUSTOM_CALLBACK.items()))
      pipe.expire(self.tmetadata.namespace, self.tmetadata.global_ttl)
      pipe.execute()

  def predict(self):
    if self.tmetadata.learningBlueMode and self.tmetadata.predictBy == 'BLUE':
      pass
      #return
    elif self.tmetadata.learningRedMode and self.tmetadata.predictBy == 'RED':
      pass
      #return

    ai_data = self.redis.zrange(self.data_namespace, 0, -1, withscores=True, as_list_of_tuples=True)

    time_x_axis, requests_y_axis = ai_data
    safe_value = self.tmetadata.learnPredictSafeValue

    if not self.is_safe(self.tmetadata.learnTimeFrameValue, len(time_x_axis), safe_value):
      return
    # 'm' for the slope and 'b' for the y-intercept of the equation y = mx + b
    (m, b) = polyfit(time_x_axis, requests_y_axis, 1)
    timeframe_current_minutes = self.get_timeframe(self.tmetadata.learnTimeFrameValue)
    # Round UP
    predicted = ceil(m * timeframe_current_minutes + b)
    if predicted < 0:
      predicted = 1
    return int(predicted * self.tmetadata.learnEscalationValue)