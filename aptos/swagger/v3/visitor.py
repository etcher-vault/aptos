from ...primitive import Creator
from ...visitor import ResolveVisitor


class OpenAPIResolveVisitor(ResolveVisitor):

    def __init__(self, context):
        self.context = context

    def visit_reference(self, reference, *args):
        if reference.resolved:  # pragma: no cover
            return reference
        # A set of reusable objects for different aspects of the OAS.
        component, name = reference.address.split('/')[-2:]
        schema = self.context['components'][component][name]
        reference.value = Creator.create(schema.get('type')).unmarshal(schema)
        reference.value.accept(self, *args)
        reference.resolved = True
        return reference

    def visit_specification(self, specification, *args):
        specification.paths.accept(self, *args)
        specification.components.accept(self, *args)
        return specification

    def visit_paths(self, paths, *args):
        for name, member in paths.items():
            paths[name] = member.accept(self, *args)

    def visit_parameters(self, parameters, *args):
        for i, element in enumerate(parameters):
            parameters[i] = element.accept(self, *args)
        return parameters

    def visit_parameter(self, parameter, *args):
        parameter.schema = parameter.schema.accept(self, *args)
        parameter.content = parameter.content.accept(self, *args)
        return parameter

    def visit_path_item(self, path_item, *args):
        path_item.parameters.accept(self, *args)
        for name, member in path_item.items():
            path_item[name] = member.accept(self, *args)
        return path_item

    def visit_responses(self, responses, *args):
        for name, member in responses.items():
            responses[name] = member.accept(self, *args)

    def visit_response(self, response, *args):
        response.content.accept(self, *args)
        return response

    def visit_content(self, content, *args):
        for name, member in content.items():
            content[name] = member.accept(self, *args)

    def visit_media_type(self, media_type, *args):
        media_type.schema.accept(self, *args)
        return media_type

    def visit_operation(self, operation, *args):
        operation.parameters.accept(self, *args)
        operation.requestBody = operation.requestBody.accept(self, *args)
        operation.responses.accept(self, *args)
        operation.callbacks.accept(self, *args)
        return operation

    def visit_request_bodies(self, request_bodies, *args):
        for name, member in request_bodies.items():
            request_bodies[name] = member.accept(self, *args)

    def visit_request_body(self, request_body, *args):
        request_body.content = request_body.content.accept(self, *args)
        return request_body

    def visit_headers(self, headers, *args):
        for name, member in headers.items():
            headers[name] = member.accept(self, *args)

    def visit_security_schemes(self, security_schemes, *args):
        for name, member in security_schemes.items():
            security_schemes[name] = member.accept(self, *args)

    def visit_callbacks(self, callbacks, *args):
        for name, member in callbacks.items():
            callbacks[name] = member.accept(self, *args)

    def visit_callback(self, callback, *args):
        for name, member in callback.items():
            callback[name] = member.accept(self, *args)

    def visit_components(self, components, *args):
        components.schemas.accept(self, *args)
        components.responses.accept(self, *args)
        components.parameters.accept(self, *args)
        components.requestBodies.accept(self, *args)
        components.headers.accept(self, *args)
        components.securitySchemes.accept(self, *args)
        components.callbacks.accept(self, *args)
        return components

    def visit_schemas(self, schemas, *args):
        for name, member in schemas.items():
            schemas[name] = member.accept(self, *args)
