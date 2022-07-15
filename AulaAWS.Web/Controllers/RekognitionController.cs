using Amazon.Rekognition;
using Amazon.Rekognition.Model;
using Microsoft.AspNetCore.Mvc;

namespace AulaAWS.Web.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class RekognitionController : ControllerBase
    {
        private readonly AmazonRekognitionClient _rekognitionClient;
        public RekognitionController(AmazonRekognitionClient rekognitionClient)
        {
            _rekognitionClient = rekognitionClient;
        }
        [HttpPost]
        public async Task<IActionResult> CompararRosto(string nameImageInS3, IFormFile imageLogin)
        {
            using (var memoryStream = new MemoryStream())
            {
                await imageLogin.CopyToAsync(memoryStream);
                var targetImage = new Image();
                targetImage.Bytes = memoryStream;

                var request = new CompareFacesRequest();
                var sourceImage = new Image();
                var s3ObjectSource = new S3Object();

                s3ObjectSource.Bucket = "aula-imagens";
                s3ObjectSource.Name = nameImageInS3;

                sourceImage.S3Object = s3ObjectSource;
                request.TargetImage = targetImage;
                request.SourceImage = sourceImage;

                var response = await _rekognitionClient.CompareFacesAsync(request);
                return Ok(response);
            }
        }
        [HttpGet]
        public async Task<IActionResult> AnalisarRosto(string nameImage)
        {
            var request = new DetectFacesRequest();

            var image = new Image();
            var s3Object = new S3Object();

            s3Object.Bucket = "aula-imagens";
            s3Object.Name = nameImage;

            image.S3Object = s3Object;
            request.Image = image;
            request.Attributes = new List<string>() { "ALL" };


            var response = await _rekognitionClient.DetectFacesAsync(request);

            var listaRostos = response.FaceDetails;

            var rostoAtual = response.FaceDetails.First();

            if ((response.FaceDetails.Count == 1) && (rostoAtual.Eyeglasses.Value == false))
                return Ok(response);
            else
                return BadRequest("Essa imagem não contém um rosto ou possui um rosto com óculos ou possui mais de um rosto!");
        }
    }
}