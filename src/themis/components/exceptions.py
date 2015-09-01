class ThemisException(Exception): pass
class InconsistencyError(ThemisException): pass
class ItemNotFound(ThemisException): pass
class RequestError(ThemisException): pass

class ApiRequestError(ThemisException):
  def __init__(self, **entries):
    Exception.__init__(self)
    entries['status_code'] = entries.get('status_code') or 400
    entries['headers'] = entries.get('headers') or {}
    self.__dict__.update(entries)