using AulaAWS.Application.DTOs;
using AulaAWS.Lib.Data.Repositorios.Interfaces;
using AulaAWS.Lib.Models;
using Microsoft.AspNetCore.Http;
using AulaAWS.Services.Services;
using Newtonsoft.Json;
using Konscious.Security.Cryptography;
using System.Text;

namespace AulaAWS.Application.Services
{
    public class UsuarioApplication : IUsuarioApplication
    {
        private readonly IUsuarioRepositorio _repositorio;
        private readonly IImagensServices _imagensServices;

        public UsuarioApplication(IUsuarioRepositorio repositorio, IImagensServices imagensServices)
        {
            _repositorio = repositorio;
            _imagensServices = imagensServices;
        }

        public async Task<string> CadastrarUsuario(UsuarioDTO usuarioDto)
        {
            var senha = await ConverterSenhaEmHash(usuarioDto.Senha);
            var usuario = new Usuario(usuarioDto.Nome, usuarioDto.Cpf, usuarioDto.DataNascimento, usuarioDto.Email, senha);
            await _repositorio.AdicionarAsync(usuario);
            var resposta = new JsonId()
            {
                Id = usuario.Id.ToString()
            };
            return JsonConvert.SerializeObject(resposta);
        }

        public async Task<List<Usuario>> ListarUsuarios()
        {
            var listaUsuarios = await _repositorio.ListarTodosAsync();
            return listaUsuarios;
        }

        public async Task AlterarSenhaUsuario(Guid id, string senha)
        {
            await _repositorio.AlterarSenhaAsync(id, senha);
        }

        public async Task DeletarUsuario(Guid id)
        {
            await _repositorio.DeletarAsync(id);
        }

        public async Task CadastrarImagemUsuario(Guid id, IFormFile imagem)
        {
            var imagemValida = await _imagensServices.ValidarImagem(imagem);
            if (!imagemValida)
                throw new Exception("Imagem inválida");

            var nomeArquivo = await _imagensServices.SalvarNoS3(imagem);
            await _repositorio.AtualizarImagemAsync(id, nomeArquivo);
        }

        public async Task<string> LoginUsuario(string email, string senha)
        {
            var usuario = await _repositorio.BuscarUsuarioPorEmail(email);
            var senhaEstaCorreta = await VerificarSenha(senha, usuario.Senha);
            if (!senhaEstaCorreta)
                throw new Exception("Senha incorreta");

            var resposta = new JsonId()
            {
                Id = usuario.Id.ToString()
            };
            return JsonConvert.SerializeObject(resposta);
        }

        public async Task<bool> LoginUsuarioImagem(Guid id, IFormFile imagem)
        {
            var usuario = await _repositorio.BuscarPorIdAsync(id);
            var imagemUsuario = await _imagensServices.BuscarImagemUsuario(usuario.UrlImagemCadastro);
            var ImagemValidada = await _imagensServices.ValidarImagemLogin(imagemUsuario, imagem);
            if (!ImagemValidada)
                throw new Exception("Foto inválida");
            return true;
        }
        private async Task<bool> VerificarSenha(string senhaLogin, string senhaUsuario)
        {
            var senha = await ConverterSenhaEmHash(senhaLogin);
            return senha == senhaUsuario;
        }

        public async Task<string> ConverterSenhaEmHash(string senha)
        {
            byte[] password = Encoding.UTF8.GetBytes(senha);
            byte[] salt = Encoding.UTF8.GetBytes("UOrd7FcW33T5gyMv");
            var argon2 = new Argon2i(password);
            argon2.DegreeOfParallelism = 10;
            argon2.MemorySize = 8192;
            argon2.Iterations = 20;
            argon2.Salt = salt;
            var hash = await argon2.GetBytesAsync(64);
            return Convert.ToBase64String(hash);
        }
    }
}