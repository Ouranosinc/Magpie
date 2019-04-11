<!DOCTYPE html>
<head>
    <meta charset="UTF-8">
    <title>${api_title}</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@3.17.5/swagger-ui.css">
    <script src="https://unpkg.com/swagger-ui-dist@3.17.5/swagger-ui-standalone-preset.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@3.17.5/swagger-ui-bundle.js"></script>
    <script>
        addEventListener('DOMContentLoaded', function() {
            var api_urls = [
                { url: "${api_schema_path}", name: 'latest' },
                // disable other versions, only use latest
                //{ url: '${api_schema_versions_dir}/magpie-rest-api-0.1.0.yaml', name: '0.1.0' },
                //{ url: '${api_schema_versions_dir}/magpie-rest-api-0.1.1.yaml', name: '0.1.1' },
                //{ url: '${api_schema_versions_dir}/magpie-rest-api-0.2.0.yaml', name: '0.2.0' },
                //{ url: '${api_schema_versions_dir}/magpie-rest-api-0.2.x.yaml', name: '0.2.x' },
                //{ url: '${api_schema_versions_dir}/magpie-rest-api-0.3.x.yaml', name: '0.3.x' },
                //{ url: '${api_schema_versions_dir}/magpie-rest-api-0.4.x.yaml', name: '0.4.x' },
                //{ url: '${api_schema_versions_dir}/magpie-rest-api-0.5.x.yaml', name: '0.5.x' },
                //{ url: '${api_schema_versions_dir}/magpie-rest-api-0.6.x.yaml', name: '0.6.x' },
            ];
            window.ui = SwaggerUIBundle({
                url: "${api_schema_path}",
                urls: api_urls,
                dom_id: '#swagger-ui',
                deepLinking: true,
                docExpansion: 'none',
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout",
                validatorUrl: null,     // disable validator error messages not finding local routes
                tagsSorter: 'alpha',
                apisSorter : "alpha",
                operationsSorter: "alpha",
            });
        });
    </script>
</head>
<body>
<div id="swagger-ui"></div>
</body>
</html>
