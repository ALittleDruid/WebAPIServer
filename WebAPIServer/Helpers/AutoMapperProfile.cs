using AutoMapper;
using WebAPIServer.Dtos;
using WebAPIServer.Model;

namespace WebAPIServer.Helpers
{
    public class AutoMapperProfile : Profile
    {
        public AutoMapperProfile()
        {
            CreateMap<User, UserDto>();
            CreateMap<UserDto, User>();
        }
    }
}
