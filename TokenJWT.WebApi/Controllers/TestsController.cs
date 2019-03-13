using System.Web.Http;

namespace TokenJWT.WebApi.Controllers
{
    [Authorize]
    [RoutePrefix("api/tests")]
    public class TestsController : ApiController
    {
        public IHttpActionResult Get()
        {
            return Ok("Success... token jwt is valid.");
        }
    }
}
