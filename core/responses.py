from rest_framework.response import Response
from django.conf import settings

class CreatedResponse(Response):
    def __init__(
        self,
        data=None,
        status=None,
        template_name=None,
        headers=None,
        exception=False,
        content_type=None,
    ):
        if isinstance(data, dict):
            new_data = data
        else:
            new_data = {"data": data}
        super().__init__(new_data, 201, template_name, headers, exception, content_type)


class GoodResponse(Response):
    def __init__(
        self,
        data=None,
        status=None,
        cookie=None,
        template_name=None,
        headers=None,
        exception=False,
        content_type=None,
        
    ):
        if isinstance(data, dict):
            new_data = data
        else:
            new_data = {"data": data}
        super().__init__(
            new_data, status, template_name, headers, exception, content_type, 
        )
        
        if isinstance(cookie, dict) and cookie is not None:
            self.set_cookie(key="access_token", value=cookie['access'])
            self.set_cookie(key="refresh_token", value=cookie['refresh'])
        
        

class DeletedResponse(Response):
    def __init__(
        self,
        data=None,
        status=None,
        template_name=None,
        headers=None,
        exception=False,
        content_type=None,
    ):
        if isinstance(data, dict):
            new_data = data
        else:
            new_data = {"data": data}
        super().__init__(new_data, 204, template_name, headers, exception, content_type)


class BadRequestResponse(Response):
    def __init__(
        self,
        message,
        code,
        data={},
        status=None,
        template_name=None,
        headers=None,
        exception=False,
        content_type=None,
        request=None,
    ):
        if settings.DEBUG:
            try:
                data["sent_data"] = request.data
            except:
                data["send_data"] = "<<ERROR>>"
        new_data = {"message": message, "code": code, "data": data}
        super().__init__(new_data, 400, template_name, headers, exception, content_type)


class NotFoundResponse(Response):
    def __init__(
        self,
        message,
        model,
        data={},
        status=None,
        template_name=None,
        headers=None,
        exception=False,
        content_type=None,
        request=None,
    ):
        if settings.DEBUG:
            data["sent_data"] = request.data
        new_data = {"message": message, "model": model, "data": data}
        super().__init__(new_data, 404, template_name, headers, exception, content_type)
        