using Microsoft.AspNetCore.Mvc;

namespace TestIntegration.Controllers
{
    [ApiController]
    [Route("api")]
    public class TestController : ControllerBase
    {
        [HttpGet("test")]
        public IActionResult GetTest()
        {
            return Ok(new { message = "Test endpoint working", timestamp = DateTime.UtcNow });
        }

        [HttpPost("users")]
        public IActionResult CreateUser([FromBody] UserDto user)
        {
            return Ok(new { message = "User created", user = user, timestamp = DateTime.UtcNow });
        }

        [HttpPut("users/{id}")]
        public IActionResult UpdateUser(int id, [FromBody] UserDto user)
        {
            return Ok(new { message = $"User {id} updated", user = user, timestamp = DateTime.UtcNow });
        }

        [HttpPost("comments")]
        public IActionResult CreateComment([FromBody] CommentDto comment)
        {
            return Ok(new { message = "Comment created", comment = comment, timestamp = DateTime.UtcNow });
        }

        [HttpPost("search")]
        public IActionResult Search([FromBody] SearchDto search)
        {
            return Ok(new { message = "Search completed", query = search.Query, timestamp = DateTime.UtcNow });
        }

        [HttpPost("execute")]
        public IActionResult Execute([FromBody] ExecuteDto execute)
        {
            return Ok(new { message = "Command executed", command = execute.Command, timestamp = DateTime.UtcNow });
        }

        [HttpGet("ratelimit")]
        public IActionResult RateLimitTest()
        {
            return Ok(new { message = "Rate limit test", timestamp = DateTime.UtcNow });
        }

        [HttpPost("large")]
        public IActionResult LargePayload([FromBody] LargeDto data)
        {
            return Ok(new { message = "Large payload processed", size = data.Data?.Length ?? 0, timestamp = DateTime.UtcNow });
        }
    }

    public class UserDto
    {
        public string? Name { get; set; }
        public string? Email { get; set; }
    }

    public class CommentDto
    {
        public string? Comment { get; set; }
    }

    public class SearchDto
    {
        public string? Query { get; set; }
    }

    public class ExecuteDto
    {
        public string? Command { get; set; }
    }

    public class LargeDto
    {
        public string? Data { get; set; }
    }
}
