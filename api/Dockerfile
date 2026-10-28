FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY . .
RUN dotnet restore api/api.csproj
RUN dotnet publish api/api.csproj --configuration Release --output /out --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /out .
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates gosu libldap2 \
    && rm -rf /var/lib/apt/lists/*
COPY api/docker-entrypoint.sh /usr/local/bin/atlas-ti-entrypoint
RUN mkdir -p /app/App_Data/DataProtectionKeys /var/lib/atlas-ti/documents \
    && chmod 755 /usr/local/bin/atlas-ti-entrypoint \
    && chown -R $APP_UID:$APP_UID /app/App_Data /var/lib/atlas-ti
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/atlas-ti-entrypoint"]
