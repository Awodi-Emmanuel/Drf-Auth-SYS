import traceback

from rest_framework.viewsets import GenericViewSet

from core.errors import BadRequestError, NotFoundError
from core.responses import BadRequestResponse


class YkGenericViewSet(GenericViewSet):
    def dispatch(self, request, *args, **kwargs):
        try:
            return super().dispatch(request, *args, **kwargs)
        except BadRequestError as e:
            return self.finalize_response(request, e.response, *args, **kwargs)
        except NotFoundError as e:
            return self.finalize_response(request, e.response, *args, **kwargs)
        except Exception as e:
            traceback.print_exc()
            return self.finalize_response(
                request,
                BadRequestResponse(traceback.format_exc(), "unknown", request=request),
            )
