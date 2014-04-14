var req = new XMLHttpRequest();
req.open('GET', "/jcsrf_static/jquery.js", false);
req.send(null);
if (req.status !== 200)
  alert(req.status);
var jcsrf = eval(req.responseText);
var debug = false;

function say(text) {
  if (debug)
    jcsrf('body').append('<pre>' + text + '</pre>');
};

// it probably needs exceptions for CORS, which is disregarded in this
// implementation.
XMLHttpRequest.prototype.old_send = XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.old_open = XMLHttpRequest.prototype.open;
function new_send(data) {
   if(this.method === "POST") {
      this.setRequestHeader("X-No-Csrf", "true");
   }
   this.old_send(data);
}
function new_open(method, url, async, username, password) {
  this.method = method;
  return this.old_open(method, url, async, username, password);
}
XMLHttpRequest.prototype.send = new_send;
XMLHttpRequest.prototype.open = new_open;

var jcsrf_token = /jcsrf-token=([^;]+)(;|$)/.exec(document.cookie)[1];

function getDomain(url) {
  // proxy doesn't work on https anyway
  if (url.indexOf("http://") !== 0)
    return document.domain;
  return /http:\/\/([^\/]+)/.exec(url)[1];
} 

function getToken(e) {
  if (getDomain(this.action) == document.domain &&
      jcsrf('input[name="jcsrf-so-token"]', this).length == 0)
  {
    /* so case does not require locking because everything is
     * synchronous. just stuff the token in */
    var newfield = "<input type='hidden' name='jcsrf-so-token'" +
      "value='" + jcsrf_token + "'/>";
    jcsrf(this).append(newfield);
  } else if (getDomain(this.action) != document.domain &&
	     jcsrf('input[name="jcsrf-co-token"]', this).length == 0)
  {
    /* 1. focus unlocked: *lock, *get the token, return.
       2. focus locked: return
       3. submit unlocked: *lock, *get the token, *set shouldSubmit to true, *prevent submit
       4. submit locked: *set shouldSubmit to true, *prevent submit
       note: the handler always unlocks */
    if (e.type == "submit") {
      jcsrf(form).data("shouldSubmit", true);
      e.preventDefault();
      e.stopPropagation();
    }

    if (!jcsrf(this).data("locked")) {
      jcsrf(this).data("locked", true);
      var iframe_url = "http://" + getDomain(this.action) + '/' +
	"jcsrf_static/jcsrf_iframe.html?origin=" + document.domain;
      var iframe = jcsrf("<iframe></iframe>");
      iframe.attr("id", "jcsrf-co-iframe");
      iframe.attr("src", iframe_url);
      var form = this;
      window.addEventListener("message", function handleCO(event) {
	// you would actually need to check the source to be == to
	// iframe
	var newfield = "<input type='hidden' name='jcsrf-co-token'" +
	  "value='" + event.data + "'/>";
	jcsrf(form).append(newfield);
	jcsrf(iframe).detach();
	if (jcsrf(form).data("shouldSubmit")) {
	  jcsrf(form).data("shouldSubmit", false);
	  form.submit();
	}
	jcsrf(form).data("locked", false);
	window.removeEventListener("message", handleCO, false);
      }, false);
      jcsrf("body").append(iframe);
    }
  }
}

/* remove jcsrf-co-token and jcsrf-so-token, run fun and then put them
 * back */
function csrf_wrap(fun) {
  return function(event) {
    var tokens = jcsrf('input[name="jcsrf-so-token"]', this).add(
      'input[name="jcsrf-co-token"]', this).detach();
    var result = fun.apply(this, [event]);
    jcsrf(this).append(tokens);
    return result;
  };
}


/* DOM2 wrapping */
HTMLFormElement.prototype.addEventListener_ = HTMLFormElement.prototype.addEventListener;
HTMLFormElement.prototype.addEventListener = function(eventType, fun, bubble)
{
  if (eventType == "submit") {
    wrapped = csrf_wrap(fun);
    this.addEventListener_(eventType, wrapped, bubble);
  } else {
    this.addEventListener_(eventType, fun, bubble);
  }
};

/* DOM0 wrapping */
function dom0_handle() {
  var handler = this.onsubmit;
  var handled = jcsrf(this).data("handled");
  // actually, this only detects the DOM0 handler once. the "handled"
  // attr is inconsistent if the web application resets a new DOM0
  // handler after this one has been wrapped.
  if (handler && handled != true) {
    jcsrf(this).data("handled", true);
    wrapped = csrf_wrap(handler);
    this.onsubmit = wrapped;
  }
}


jcsrf(document).ready(function() {
  jcsrf('form[method="POST"]').live('focus', getToken);
  jcsrf('form[method="POST"]').live('submit', getToken);
  setInterval(function() {
    jcsrf('form[method="POST"]').each(dom0_handle);
  }, 1000);
});
