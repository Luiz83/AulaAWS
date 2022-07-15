using AulaAWS.Lib.Data.Repositorios.Interfaces;
using AulaAWS.Lib.Models;

namespace AulaAWS.Lib.Data.Repositorios
{
    public class UsuarioRepositorio : RepositorioBase<Usuario>, IUsuarioRepositorio
    {
        private readonly AWSLoginContext _context;
        public UsuarioRepositorio(AWSLoginContext context) : base(context, context.Usuarios)
        {
            _context = context;
        }

        public async Task AlterarSenhaAsync(int id, string senha)
        {
            var usuario = await _dbset.FindAsync(id);
            usuario.SetSenha(senha);
            await _context.SaveChangesAsync();
        }
        public async Task AtualizarImagemAsync(int id, string nomeArquivo)
        {
            var usuario = await _dbset.FindAsync(id);
            usuario.SetUrlImagem(nomeArquivo);
            await _context.SaveChangesAsync();
        }
    }
}