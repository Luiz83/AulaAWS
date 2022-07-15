using AulaAWS.Lib.Data.Repositorios.Interfaces;
using AulaAWS.Lib.Models;
using Microsoft.EntityFrameworkCore;

namespace AulaAWS.Lib.Data.Repositorios
{
    public class RepositorioBase<T> : IRepositorioBase<T> where T : ModelBase
    {
        protected readonly AWSLoginContext _context;
        protected readonly DbSet<T> _dbset;

        public RepositorioBase(AWSLoginContext context, DbSet<T> dbset)
        {
            _context = context;
            _dbset = dbset;
        }

        public async Task<List<T>> ListarTodosAsync()
        {
            return await _dbset.AsNoTracking().ToListAsync();
        }
        public async Task<T> BuscarPorIdAsync(int id)
        {
            return await _dbset.AsNoTracking().FirstAsync(x => x.Id == id);
        }
        public async Task AdicionarAsync(T item)
        {
            await _dbset.AddAsync(item);
            await _context.SaveChangesAsync();
        }
        public async Task DeletarAsync(int id)
        {
            var item = await _dbset.FindAsync(id);
            _dbset.Remove(item);
            await _context.SaveChangesAsync();
        }
    }
}