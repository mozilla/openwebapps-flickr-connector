#!/usr/bin/env python
#
import tornado.httpserver
import tornado.auth
import tornado.ioloop
import tornado.web
import os
import base64
import json
import hashlib
import urllib
import cStringIO
import mimetools
import sys

# search for server configuration (API keys and such)
CONFIG_FILE_NAME = 'config.py'
if os.path.exists(CONFIG_FILE_NAME):
  import config
elif os.path.exists(os.path.join("..", CONFIG_FILE_NAME)):
  sys.path.append('..')
  import config
  sys.path.pop()
else:
  raise RuntimeError('no configuration file found: %s' % CONFIG_FILE_NAME)

class WebHandler(tornado.web.RequestHandler):
  def get_current_user(self):
    return self.get_secure_cookie("uid")

  def get_error_html(self, status_code, **kwargs):
    return "<html><title>Error!</title><style>.box {margin:16px;padding:8px;border:1px solid black;font:14pt Helvetica,arial} "\
            ".small {text-align:right;color:#888;font:italic 8pt Helvetica;}</style>" \
           "<body><div class='box'>We're sorry, something went wrong!<br><br>Perhaps "\
           "you should <a href='/'>return to the front page.</a><br><br><div class='small'>%s %s</div></div>" % (
          status_code, kwargs['exception'])

  def render_platform(self, file, templates=False, **kwargs):
    target_file = file

    if  "User-Agent" in self.request.headers:
      UA = self.request.headers["User-Agent"]
      if UA.find("iPhone") >= 0:
        target_file = target_file + "_iphone"
    if self.get_argument("cloak", None):
      target_file = file + "_" + self.get_argument("cloak", None)

    tmpl = None
    if templates:
      f = open(target_file + ".tmpl", "r")
      tmpl = f.read()
      f.close() # cache this

    self.render(target_file + ".html", templates=tmpl, **kwargs)

  # Put auth_token in before you call this
  def sign_request(self, request):
    sigval = config.KEYS["flickrSecret"]
    keys = request.keys()
    keys.sort()
    for k in keys:
      sigval += unicode(k)
      sigval += unicode(request[k])
    sighash = hashlib.md5(sigval).hexdigest()
    return sighash
            
# General, and user administration, handlers
class MainHandler(WebHandler):
  def get(self):
    self.set_header("X-XRDS-Location", "%s/xrds" % config.DOMAIN)
    self.render_platform("index", newCredentials=False, credentials=None, errorMessage=None)

class XRDSHandler(WebHandler):
  def get(self):
    self.set_header("Content-Type", "application/xrds+xml")
    self.write("""<?xml version="1.0" encoding="UTF-8"?>"""\
      """<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns:openid="http://openid.net/xmlns/1.0" xmlns="xri://$xrd*($v*2.0)">"""\
      """<XRD><Service priority="1"><Type>https://specs.openid.net/auth/2.0/return_to</Type>"""\
      """<URI>%s/login</URI>"""\
      """</Service></XRD></xrds:XRDS>""" % config.DOMAIN)

class FlickrConnectDone(WebHandler):
  @tornado.web.asynchronous
  def get(self):
    frob = self.get_argument("frob", None)
    if not frob:
      raise Exception("Failed Flickr authentication")
    
    sigval = config.KEYS["flickrSecret"] + "api_key" + config.KEYS["flickrAPIKey"] + "formatjson" + "frob" + frob + "methodflickr.auth.getTokennojsoncallback1"
    #+ "formatjsonnojsoncallback1"
    sighash = hashlib.md5(sigval).hexdigest()

    url = "http://api.flickr.com/services/rest/?method=flickr.auth.getToken&api_key=" + config.KEYS["flickrAPIKey"] + "&frob=" + frob + "&format=json&nojsoncallback=1&api_sig=" + sighash
    #+ "&format=json&nojsoncallback=1&api_sig=" + sighash
    http = tornado.httpclient.AsyncHTTPClient()
    http.fetch(url,  callback=self.on_response)

  def on_response(self, response):
    if response.error: raise tornado.web.HTTPError(500)
    #json = tornado.escape.json_decode(response.body)

    # response body looks like this:   {"auth":{"token":{"_content":"72157626196623223-9271de4a076fd149"}, "perms":{"_content":"read"}, 
    # "user":{"nsid":"48465434@N07", "username":"michaelrhanson", "fullname":""}}, "stat":"ok"}
    try:
      result = json.loads(response.body)
      if result["stat"] != "ok":
        self.write("Whoops, sorry, something didn't work right.  There was an error returned by Flickr.")
        self.finish()
        logging.error(response.body)
      else:
        self.render_platform("index", newCredentials=True, credentials=result)
    except Exception, e:
      self.write("Whoops, sorry, something didn't work right.  There was an error in our application.")
      self.finish()
      logging.error(e)

class FlickrConnect(WebHandler):
  def get(self):
    # http://flickr.com/services/auth/?api_key=[api_key]&perms=[perms]&api_sig=[api_sig]
    
    sigval = config.KEYS["flickrSecret"] + "api_key" + config.KEYS["flickrAPIKey"] + "permswrite"
    sighash = hashlib.md5(sigval).hexdigest()
    url = "http://flickr.com/services/auth/?api_key=%s&perms=write&api_sig=%s" % (config.KEYS["flickrAPIKey"], sighash)
    self.redirect(url)

class GetFlickrPhotos(WebHandler):
  @tornado.web.asynchronous
  def get(self):
    flickrUserId = self.get_argument("userid", None)
    if not flickrUserId:
      raise Exception("Missing required flickrUserId")
      
    http = tornado.httpclient.AsyncHTTPClient()
    url = "http://api.flickr.com/services/rest/?method=flickr.photosets.getList&api_key=" + config.KEYS["flickr"] + "&user_id=" + flickrUserid + "&format=json&nojsoncallback=1"
    http.fetch(url,  callback=self.on_response)

  def on_response(self, response):
    if response.error: raise tornado.web.HTTPError(500)
    json = tornado.escape.json_decode(response.body)
    self.write("Got something: " + response.body)

class GetPhotosets(WebHandler):
  @tornado.web.asynchronous
  def get(self):
    flickrUserId = self.get_argument("usernsid", None)
    if not flickrUserId:
      raise Exception("Missing required usernsid")
    authToken = self.get_argument("token", None)
    if not authToken:
      raise Exception("Missing required token")
      
    http = tornado.httpclient.AsyncHTTPClient()
    request = {
      "auth_token":authToken,
      "api_key": config.KEYS["flickrAPIKey"],
      "method":"flickr.photosets.getList",
      "user_id":flickrUserId,
      "format":"json",
      "nojsoncallback":1,
    }
    signature = self.sign_request(request)
    request["api_sig"] = signature
    req = ["%s=%s" % (key, request[key]) for key in request.keys()] # XX urlescape
    url = "http://api.flickr.com/services/rest/?%s" % "&".join(req)
    http.fetch(url,  callback=self.on_response)

  def on_response(self, response):
    if response.error: raise tornado.web.HTTPError(500)
    json = tornado.escape.json_decode(response.body)
    self.write(response.body)
    self.finish()

class GetPhotos(WebHandler):
  @tornado.web.asynchronous
  def get(self):
    photosetID = self.get_argument("photosetid", None)
    if not photosetID:
      raise Exception("Missing required photosetid")
    authToken = self.get_argument("token", None)
    if not authToken:
      raise Exception("Missing required token")
      
    http = tornado.httpclient.AsyncHTTPClient()
    request = {
      "auth_token":authToken,
      "api_key": config.KEYS["flickrAPIKey"],
      "method":"flickr.photosets.getPhotos",
      "photoset_id": photosetID,
      "extras": "url_sq,url_t,url_s,url_m,url_z,url_l,url_o,icon_server,tags",
      "format":"json",
      "nojsoncallback":1,
    }
    signature = self.sign_request(request)
    request["api_sig"] = signature
    req = ["%s=%s" % (key, request[key]) for key in request.keys()] # XX urlescape
    url = "http://api.flickr.com/services/rest/?%s" % "&".join(req)
    http.fetch(url,  callback=self.on_response)

  def on_response(self, response):
    if response.error: raise tornado.web.HTTPError(500)
    json = tornado.escape.json_decode(response.body)
    self.write(response.body)
    self.finish()


class GetPhotoSizes(WebHandler):
  @tornado.web.asynchronous
  def get(self):
    photoID = self.get_argument("photoid", None)
    if not photoid:
      raise Exception("Missing required photoid")
    authToken = self.get_argument("token", None)
    if not authToken:
      raise Exception("Missing required token")
      
    http = tornado.httpclient.AsyncHTTPClient()
    request = {
      "auth_token":authToken,
      "api_key": config.KEYS["flickrAPIKey"],
      "method":"flickr.photos.getSizes",
      "photo_id": photoID,
      "format":"json",
      "nojsoncallback":1,
    }
    signature = self.sign_request(request)
    request["api_sig"] = signature
    req = ["%s=%s" % (key, request[key]) for key in request.keys()] # XX urlescape
    url = "http://api.flickr.com/services/rest/?%s" % "&".join(req)
    http.fetch(url,  callback=self.on_response)

  def on_response(self, response):
    if response.error: raise tornado.web.HTTPError(500)
    json = tornado.escape.json_decode(response.body)
    self.write(response.body)
    self.finish()

class PostPhoto(WebHandler):
  @tornado.web.asynchronous
  def post(self):
    try:
      photo = self.get_argument("photo") #base64ed?
      title = self.get_argument("title", None)
      description = self.get_argument("description", None)
      tags = self.get_argument("tags", None) # space-separated
      # maybe hidden?
      
      authToken = self.get_argument("token")
      
      http = tornado.httpclient.AsyncHTTPClient()
      request = {
        "auth_token":authToken,
        "api_key": config.KEYS["flickrAPIKey"],
      }
      if description: request["description"] = description
      if title: request["title"] = title
      if tags: request["tags"] = tags

      signature = self.sign_request(request)
      request["api_sig"] = signature
      
      photoFile = cStringIO.StringIO(base64.b64decode(photo));
#      files = {"thefile": photoFile}
      boundary, body = multipart_encode(request.items(), [ ("photo", "thefile.jpg", photoFile, "image/jpg" ) ])

      headers = { "Content-Type": "multipart/form-data; boundary=" + boundary }

      httpRequest = tornado.httpclient.HTTPRequest(
        "http://api.flickr.com/services/upload/",
        method = "POST",
        headers = headers,
        body = body
      )
      
      http.fetch(httpRequest,  callback=self.on_response)
    except Exception, e:
      logging.exception(e)
      raise tornado.web.HTTPError(500)

  def on_response(self, response):
    logging.error(response.body)
    
    if response.error: 
      logging.error(response.error)
      raise tornado.web.HTTPError(500)
    
    # Response is always XML
    # TODO parse the XML. :)
    #json = tornado.escape.json_decode(response.body)
    self.write(response.body)
    self.finish()


def multipart_encode(vars, files, boundary = None, buf = None):
    if boundary is None:
        boundary = mimetools.choose_boundary()
    if buf is None:
        buf = cStringIO.StringIO()
    for(key, value) in vars:
        buf.write('--%s\r\n' % boundary)
        buf.write('Content-Disposition: form-data; name="%s"' % key)
        buf.write('\r\n\r\n' + value + '\r\n')
    for(name, filename, file, contenttype) in files:
        file.seek(os.SEEK_END)
        file_size = file.tell()
        file.seek(os.SEEK_SET)
        buf.write('--%s\r\n' % boundary)
        buf.write('Content-Disposition: form-data; name="%s"; filename="%s"\r\n' % (name, filename))
        buf.write('Content-Type: %s\r\n' % contenttype)
        # buffer += 'Content-Length: %s\r\n' % file_size
        buf.write('\r\n' + file.read() + '\r\n')
    buf.write('--' + boundary + '--\r\n\r\n')
    buf = buf.getvalue()
    return boundary, buf

class Service_GetImage(WebHandler):
  def get(self):
    self.render("service_getImage.html")

class Service_SendImage(WebHandler):
  def get(self):
    self.render("service_sendImage.html")

class WebAppManifestHandler(WebHandler):
  def get(self):
    self.set_header("Content-Type", "application/x-web-app-manifest+json")
    self.render("flickrconnector.webapp")


##################################################################
# Main Application Setup
##################################################################

settings = {
    "static_path": os.path.join(os.path.dirname(__file__), "static"),
    "cookie_secret": config.cookie_secret,
    "login_url": "/login",
    "debug":True,
    "xheaders":True,
#    "xsrf_cookies": True,
}

application = tornado.web.Application([
    (r"/flickr.webapp", WebAppManifestHandler),
    (r"/connect/done", FlickrConnectDone),
    (r"/connect/start", FlickrConnect),
    (r"/get/photosets", GetPhotosets),
    (r"/get/photos", GetPhotos),
    (r"/get/photosizes", GetPhotoSizes),
    (r"/post/photo", PostPhoto),
    (r"/retrieve", GetFlickrPhotos),
    (r"/service/getImage", Service_GetImage),
    (r"/service/sendImage", Service_SendImage),
    (r"/xrds", XRDSHandler),
    (r"/", MainHandler),
 
	], **settings)


def run():
    http_server = tornado.httpserver.HTTPServer(application)
    http_server.listen(8410)
    
    print "Starting server on 8410"
    tornado.ioloop.IOLoop.instance().start()
		
import logging
import sys
if __name__ == '__main__':
	if '-test' in sys.argv:
		import doctest
		doctest.testmod()
	else:
		logging.basicConfig(level = logging.DEBUG)
		run()
	
	
