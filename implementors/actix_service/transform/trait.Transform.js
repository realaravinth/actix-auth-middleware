(function() {var implementors = {};
implementors["actix_auth_middleware"] = [{"text":"impl&lt;S, GT&gt; Transform&lt;S, ServiceRequest&gt; for <a class=\"struct\" href=\"actix_auth_middleware/struct.Authentication.html\" title=\"struct actix_auth_middleware::Authentication\">Authentication</a>&lt;GT&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;S: Service&lt;ServiceRequest, Response = ServiceResponse&lt;AnyBody&gt;, Error = Error&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;S::Future: 'static,<br>&nbsp;&nbsp;&nbsp;&nbsp;GT: <a class=\"trait\" href=\"actix_auth_middleware/trait.GetLoginRoute.html\" title=\"trait actix_auth_middleware::GetLoginRoute\">GetLoginRoute</a>,&nbsp;</span>","synthetic":false,"types":["actix_auth_middleware::Authentication"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()