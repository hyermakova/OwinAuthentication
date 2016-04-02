using System.Web.Mvc;
using System.Web.Routing;

namespace IdentitySample {
    public class RouteConfig {
        public static void RegisterRoutes(RouteCollection routes) {
            routes.IgnoreRoute("{resource}.axd/{*pathInfo}");

            routes.MapRoute(
                name: "Default",
                url: "{controller}/{action}/{id}",
                defaults: new { controller = "Home", action = "Index", id = UrlParameter.Optional }
            );

            routes.MapRoute(name: "signin-google", url: "signin-google", defaults: new { controller = "Account", action = "ExternalLoginCallback" });
            routes.MapRoute(name: "signin-linkedin", url: "signin-linkedin", defaults: new { controller = "Account", action = "ExternalLoginCallback" });
        }
    }
}