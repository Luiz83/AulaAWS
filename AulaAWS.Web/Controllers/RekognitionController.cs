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
        [HttpGet]
        public async Task<IActionResult> AnalisarRosto(string nameImage)
        {
            var request = new DetectFacesRequest();
            request.Attributes = new List<string>() { "ALL" };
            var image = new Image();
            var s3Object = new S3Object();

            s3Object.Bucket = "aula-imagens";
            s3Object.Name = nameImage;

            image.S3Object = s3Object;
            request.Image = image;


            var response = await _rekognitionClient.DetectFacesAsync(request);

            var listaRostos = response.FaceDetails;

            var rostoAtual = response.FaceDetails.First();
            
            if ((response.FaceDetails.Count() == 1) & (rostoAtual.Eyeglasses.Value == false))
                return Ok(response);
            else
                return BadRequest("Essa imagem não contém um rosto ou possui um rosto com óculos ou possui mais de um rosto!");
        }
    }
}