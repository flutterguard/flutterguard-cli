package analyzer

import models "github.com/flutterguard/flutterguard-cli/models"

func (a *Analyzer) generateSummary(results *models.Results) models.AnalysisSummary {
    totalURLs := len(results.URLs.HTTP) + len(results.URLs.HTTPS) + len(results.URLs.FTP) +
        len(results.URLs.WS) + len(results.URLs.WSS) + len(results.URLs.File) +
        len(results.URLs.Content) + len(results.URLs.Other)

    dangerousCount := 0
    for _, perm := range results.Permissions {
        if perm.Dangerous {
            dangerousCount++
        }
    }

    var totalFiles, uniqueExt int
    var totalBytes int64
    if results.FileTypes != nil {
        totalFiles = results.FileTypes.TotalFiles
        uniqueExt = results.FileTypes.UniqueExtensions
        totalBytes = results.FileTypes.TotalBytes
    }

    return models.AnalysisSummary{
        TotalEmails:            len(results.Emails),
        TotalDomains:           len(results.Domains),
        TotalURLs:              totalURLs,
        TotalPhoneNumbers:      len(results.PhoneNumbers),
        TotalAPIEndpoints:      len(results.APIEndpoints),
        TotalEndpointsNoDomain: len(results.EndpointsNoDomain),
        TotalHTTPRequests:      len(results.HTTPRequests),
        TotalRequestHeaders:    len(results.RequestHeaders),
        TotalMethodChannels:    len(results.MethodChannels),
        TotalPackages:          len(results.Packages),
        TotalImports:           len(results.Imports),
        TotalServices:          len(results.Services),
        TotalPermissions:       len(results.Permissions),
        DangerousPermissions:   dangerousCount,
        TotalEnvFiles:          len(results.EnvFiles),
        TotalConfigFiles:       len(results.ConfigFiles),
        TotalContentFiles:      len(results.ContentFiles),
        TotalVisualAssets:      len(results.VisualAssets),
        TotalFiles:             totalFiles,
        UniqueExtensions:       uniqueExt,
        TotalFileBytes:         totalBytes,
        HasSQLCommands:         len(results.SQLCommands) > 0,
        HasSQLiteDatabases:     len(results.SQLiteDatabases) > 0,
    }
}
