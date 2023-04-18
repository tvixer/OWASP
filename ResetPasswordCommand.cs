using Application.Features.User.Errors;
using Application.Services;
using Application.Services.TokenServices;
using Ftsoft.Application.Cqs.Mediatr;
using Ftsoft.Common.Result;
using Infrastructure.Storage.Repositories;
using Microsoft.AspNetCore.Mvc;

namespace Application.Features.Auth;

public class ResetPasswordCommand : Command
{
    [FromBody] public string Token { get; set; }
    [FromBody] public string NewPassword { get; set; }
}

public sealed class ResetPasswordCommandHandler : CommandHandler<ResetPasswordCommand>
{
    private readonly UserRepository _userRepository;
    private readonly IResetTokenService _tokenService;
    private readonly ICryptService _cryptService;


    public ResetPasswordCommandHandler(UserRepository userRepository, IResetTokenService tokenService,
        ICryptService cryptService)
    {
        _userRepository = userRepository;
        _tokenService = tokenService;
        _cryptService = cryptService;
    }

    public override async Task<Result> Handle(ResetPasswordCommand request, CancellationToken cancellationToken)
    {
        var token = _tokenService.Use(request.Token);
        if (token == null)
            return Error(NotFoundError.Instance);
        var user = await _userRepository.SingleOrDefaultAsync(
            x => x.Id == token.UserId && !x.IsBanned, cancellationToken);
        if (user == null)
            return Error(NotFoundError.Instance);
        var hashedPassword = _cryptService.Hash(request.NewPassword);
        user.ChangePassword(hashedPassword);
        await _userRepository.UnitOfWork.SaveChangesAsync(cancellationToken);
        return Successful();
    }
}