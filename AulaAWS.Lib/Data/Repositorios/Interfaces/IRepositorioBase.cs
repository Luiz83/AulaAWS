using AulaAWS.Lib.Models;

namespace AulaAWS.Lib.Data.Repositorios.Interfaces
{
    public interface IRepositorioBase<T> where T : ModelBase
    {
        public Task<List<T>> ListarTodosAsync();
        public Task<T> BuscarPorIdAsync(int id);
        public Task AdicionarAsync(T item);
        public Task DeletarAsync(int id);
    }
}