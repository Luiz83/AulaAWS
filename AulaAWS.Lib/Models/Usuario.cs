namespace AulaAWS.Lib.Models
{
    public class Usuario : ModelBase
    {
        public string Nome { get; private set; }
        public string Cpf { get; private set; }
        public DateTime DataNascimento { get; private set; }
        public string Email { get; private set; }
        public string Senha { get; private set; }
        public string? UrlImagemCadastro { get; private set; }
        public DateTime DataCriacao { get; private set; }

        public Usuario(string nome, string cpf, DateTime dataNascimento, string email, string senha) : base(Guid.NewGuid())
        {
            SetNome(nome);
            SetCpf(cpf);
            SetDataNascimento(dataNascimento);
            SetEmail(email);
            SetSenha(senha);
            DataCriacao = DateTime.UtcNow;
        }
        public bool ValidarSeDataNascimentoAnterior2010(DateTime dataNascimento)
        {
            if (dataNascimento < DateTime.Parse("01/01/2010"))
                return true;
            throw new Exception();
        }
        public bool ValidarSeEmailValido(string email)
        {
            if (email.Contains("@"))
                return true;
            throw new Exception();
        }
        public bool ValidarSeCpfPossuiOnzeDigitosEApenasNumeros(string cpf)
        {
            if ((cpf.Count() <= 11) & cpf.All(char.IsNumber))
                return true;
            throw new Exception("Cpf invalido, digite apenas números!");
        }
        public bool ValidarSeSenhaPossuiPeloMenosOitoDigitos(string senha)
        {
            if (senha.Count() > 8)
                return true;
            throw new Exception();
        }
        public void SetNome(string nome)
        {
            Nome = nome;
        }
        public void SetCpf(string cpf)
        {
            ValidarSeCpfPossuiOnzeDigitosEApenasNumeros(cpf);
            Cpf = cpf;
        }
        public void SetDataNascimento(DateTime dataNascimento)
        {
            ValidarSeDataNascimentoAnterior2010(dataNascimento);
            DataNascimento = dataNascimento;
        }
        public void SetEmail(string email)
        {
            ValidarSeEmailValido(email);
            Email = email;
        }
        public void SetSenha(string senha)
        {
            ValidarSeSenhaPossuiPeloMenosOitoDigitos(senha);
            Senha = senha;
        }
        public void SetUrlImagem(string urlImagem)
        {
            UrlImagemCadastro = urlImagem;
        }
    }
}