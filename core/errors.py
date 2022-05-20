from core.responses import BadRequestResponse, NotFoundResponse


class BadRequestError(Exception):
    def __init__(self, message, code, request, *args, **kwargs):
        super().__init__(message)
        self.message = message
        self.code = code
        self.request = request
        self.response = BadRequestResponse(
            self.message, self.code, request=self.request, data=kwargs.get("data", {})
        )


class NotFoundError(Exception):
    def __init__(self, message, model, request, *args, **kwargs):
        super().__init__(message)
        self.message = message
        self.model = model
        self.request = request
        self.response = NotFoundResponse(
            self.message, self.model, request=self.request, data=kwargs.get("data", {})
        )
