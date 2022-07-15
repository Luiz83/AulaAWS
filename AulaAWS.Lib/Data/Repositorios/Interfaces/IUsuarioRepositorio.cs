using AulaAWS.Lib.Models;

namespace AulaAWS.Lib.Data.Repositorios.Interfaces
{
    public interface IUsuarioRepositorio : IRepositorioBase<Usuario>
    {
        public Task AlterarSenhaAsync(int id, string senha);
        public Task AtualizarImagemAsync(int id, string nomeArquivo);
    }
}