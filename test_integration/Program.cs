using SecureAPIs;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}

// Enable request body buffering BEFORE the security middleware
app.Use(async (context, next) =>
{
    context.Request.EnableBuffering();
    await next();
});

app.UseHttpsRedirection();

// Use SecureAPIs middleware
app.UseSecureAPIs(config =>
{
    config.RateLimitRequests = 100;
    config.RateLimitWindowSeconds = 60;
    config.EnableInputValidation = true;  // Re-enable input validation
    config.EnableCors = false;
    config.EnableSecurityHeaders = true;
});

app.UseAuthorization();

app.MapControllers();

app.MapGet("/", () => "Hello World!");
app.MapGet("/health", () => "OK");

app.Run();
