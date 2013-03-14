import base64, hashlib, hmac

class SignedRequest(object):
  
  # Construct a SignedRequest based on the stringified version of it.
  def __init__(self,consumerSecret, signedRequest):
    self.consumerSecret = consumerSecret
    self.signedRequest = signedRequest

  # Validates the signed request by verifying the key, then returns
  # the json string.
  def verifyAndDecode(self):

    # Validate secret and signed request string.
    if self.consumerSecret == None:
      raise AttributeError('No consumer secret found in environment [CANVAS_CONSUMER_SECRET].') 
    
    if self.signedRequest == None:
      raise AttributeError('Signed request parameter required.') 

    # 1) Split the signed request into signature and payload.
    request_array = self.signedRequest.split('.')
    
    if len(request_array) != 2:
      raise AttributeError('Incorrectly formatted signed request.') 

    signature = request_array[0]
    payload = request_array[1]

    # 2) Verify the contents of the payload by first validating the authenticity
    #    of the signature.
    decodedSignature = base64.b64decode(signature)

    this_hmac = hmac.new(self.consumerSecret,payload,hashlib.sha256)
    
    if decodedSignature != this_hmac.digest():
      raise Exception('Signed request has been tampered with.') 
    
    # 3) Decode the base64 encoded payload of the canvas request.
    jsonString = base64.b64decode(payload)

    return jsonString