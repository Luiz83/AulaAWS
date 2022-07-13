using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.AspNetCore.Mvc;

namespace AulaAWS.Web.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ImagesController : ControllerBase
    {
        private readonly IAmazonS3 _amazonS3;
        private readonly List<string> _imageFormats = new List<string>() { "image/jpeg", "image/png" };

        public ImagesController(IAmazonS3 amazonS3)
        {
            _amazonS3 = amazonS3;
        }

        [HttpPost]
        public async Task<IActionResult> CreateImage(IFormFile image)
        {
            if (!_imageFormats.Contains(image.ContentType))
                return BadRequest("Tipo Inválido");
            using (var imageStream = new MemoryStream())
            {
                image.CopyToAsync(imageStream);

                var request = new PutObjectRequest();
                request.Key = "reconhecimento-" + image.FileName;
                request.BucketName = "aula-imagens";
                request.InputStream = imageStream;

                var response = await _amazonS3.PutObjectAsync(request);
                return Ok(response);
            }
        }
        [HttpDelete]
        public async Task<IActionResult> DeleteImage(string nameImageInS3)
        {
            var response = await _amazonS3.DeleteObjectAsync("aula-imagens", nameImageInS3);
            return Ok(response);
        }
        [HttpPost("bucket")]
        public async Task<IActionResult> CreateBucket(string nameBucket)
        {
            var response = await _amazonS3.PutBucketAsync(nameBucket);
            return Ok(response);
        }
        [HttpGet("bucket")]
        public async Task<IActionResult> ReadBucket()
        {
            var response = await _amazonS3.ListBucketsAsync();
            return Ok(response.Buckets);
        }
    }
}