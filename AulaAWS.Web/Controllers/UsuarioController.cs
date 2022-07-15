using Microsoft.AspNetCore.Mvc;
using AulaAWS.Lib.Models;
using AulaAWS.Web.DTOs;
using AulaAWS.Lib.Data.Repositorios.Interfaces;
using Amazon.S3.Model;
using Amazon.S3;
using Amazon.Rekognition.Model;
using Amazon.Rekognition;

namespace AulaAWS.Web.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class UsuarioController : ControllerBase
    {
        private readonly IUsuarioRepositorio _repositorio;
        private readonly IAmazonS3 _amazonS3;
        private readonly AmazonRekognitionClient _rekognitionClient;
        public static List<Usuario> ListaUsuarios { get; set; } = new List<Usuario>();
        private readonly List<string> _imageFormats = new List<string>() { "image/jpeg", "image/png" };

        public UsuarioController(IUsuarioRepositorio repositorio, IAmazonS3 amazonS3, AmazonRekognitionClient rekognitionClient)
        {
            _repositorio = repositorio;
            _amazonS3 = amazonS3;
            _rekognitionClient = rekognitionClient;
        }

        [HttpGet]
        public async Task<IActionResult> ListarTodos()
        {
            return Ok(await _repositorio.ListarTodosAsync());
        }
        [HttpGet("Login")]
        public async Task<IActionResult> Login(string email, string senhaLogin)
        {
            var usuario = await BuscarUsuarioPorEmail(email);
            var senhaEstaCorreta = await VerificarSenha(senhaLogin, usuario.Senha);
            if (senhaEstaCorreta)
                return Ok(usuario.Id);
            else
                return BadRequest("Senha inválida");
        }
        [HttpPost]
        public async Task<IActionResult> Adicionar(UsuarioDTO usuarioDto)
        {
            var usuario = new Usuario(usuarioDto.Id, usuarioDto.Nome, usuarioDto.Cpf, usuarioDto.DataNascimento, usuarioDto.Email, usuarioDto.Senha);
            await _repositorio.AdicionarAsync(usuario);
            return Ok(usuario);
        }
        [HttpPost("imagem")]
        public async Task<IActionResult> AdicionarImagem(int id, IFormFile imagem)
        {
            var nomeArquivo = await SalvarNoS3(imagem);
            var imagemValida = await ValidarImagem(nomeArquivo);
            if (imagemValida)
            {
                await _repositorio.AtualizarImagemAsync(id, nomeArquivo);
                return Ok();
            }
            else
                return BadRequest();
        }
        [HttpPut]
        public async Task<IActionResult> Alterar(int id, string senha)
        {
            await _repositorio.AlterarSenhaAsync(id, senha);
            return Ok("Senha alterada com sucesso!");
        }
        [HttpDelete]
        public async Task<IActionResult> Deletar(int id)
        {
            await _repositorio.DeletarAsync(id);
            return Ok("Usuario removido com sucesso!");
        }
        private async Task<string> SalvarNoS3(IFormFile imagem)
        {
            if (!_imageFormats.Contains(imagem.ContentType))
                throw new Exception("Tipo inválido da imagem");
            using (var imagemStream = new MemoryStream())
            {
                await imagem.CopyToAsync(imagemStream);

                var request = new PutObjectRequest();
                request.Key = "reconhecimento" + imagem.FileName;
                request.BucketName = "aula-imagens";
                request.InputStream = imagemStream;

                await _amazonS3.PutObjectAsync(request);
                return request.Key;
            }
        }
        private async Task<bool> ValidarImagem(string nomeArquivo)
        {
            var request = new DetectFacesRequest();

            var image = new Image();
            var s3Object = new Amazon.Rekognition.Model.S3Object();

            s3Object.Bucket = "aula-imagens";
            s3Object.Name = nomeArquivo;

            image.S3Object = s3Object;
            request.Image = image;
            request.Attributes = new List<string>() { "ALL" };

            var response = await _rekognitionClient.DetectFacesAsync(request);

            if ((response.FaceDetails.Count == 1) && (response.FaceDetails.First().Eyeglasses.Value == false))
                return true;
            else
                await _amazonS3.DeleteObjectAsync("aula-imagens", nomeArquivo);
            return false;
        }
        private async Task<Usuario> BuscarUsuarioPorEmail(string email)
        {
            var listaUsuarios = await _repositorio.ListarTodosAsync();
            var usuario = listaUsuarios.Find(x => x.Email == email);
            if(usuario != null)
                return usuario;
            else    
                throw new Exception("Nenhum usuario foi encontrado com esse email!");
        }
        private async Task<bool> VerificarSenha(string senhaLogin, string senhaUsuario)
        {
            if (senhaLogin == senhaUsuario)
                return true;
            else
                return false;
        }
    }
}