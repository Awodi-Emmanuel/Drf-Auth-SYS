from drf_yasg import openapi
from drf_yasg.inspectors import PaginatorInspector
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response


class MetadataPagination(PageNumberPagination):
    def get_paginated_response(self, data):
        model = self.page.paginator.object_list.model
        if model._meta.verbose_name_plural:
            plural = model._meta.verbose_name_plural.lower()
        elif model._meta.verbose_name:
            plural = f"{model._meta.verbose_name.lower()}s"
        else:
            plural = f"{model.__name__.lower()}s"

        return Response(
            {
                plural: data,
                "metadata": {
                    "total_elements": self.page.paginator.count,
                    "total_pages": self.page.paginator.num_pages,
                    "count": len(data),
                    "current_page": self.page.number,
                    "previous_page": self.page.previous_page_number()
                    if self.page.has_previous()
                    else None,
                    "next_page": self.page.next_page_number()
                    if self.page.has_next()
                    else None,
                },
            }
        )

    def get_paginated_response_schema(self, schema):
        return {
            "type": "object",
            "properties": {
                "metadata": {
                    "type": "object",
                    "properties": {
                        "total_elements": {"type": "integer", "example": 1230},
                        "total_pages": {"type": "integer", "example": 6},
                        "count": {"type": "integer", "example": 123},
                        "current_page": {"type": "integer", "example": 3},
                        "next_page": {
                            "type": "integer",
                            "example": 4,
                            "nullable": True,
                        },
                        "previous_page": {
                            "type": "integer",
                            "example": 2,
                            "nullable": True,
                        },
                    },
                    "model_name_plural": schema,
                }
            },
        }


class MetadataPaginatorInspector(PaginatorInspector):
    def get_paginated_response(self, paginator, response_schema):
        path = self.path.split("/")[-2]
        paged_schema = openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                path: response_schema,
                "metadata": openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "total_elements": openapi.Schema(
                            type=openapi.TYPE_INTEGER, example=1230
                        ),
                        "total_pages": openapi.Schema(
                            type=openapi.TYPE_INTEGER, example=12
                        ),
                        "count": openapi.Schema(type=openapi.TYPE_INTEGER, example=100),
                        "current_page": openapi.Schema(
                            type=openapi.TYPE_INTEGER, example=3
                        ),
                        "next_page": openapi.Schema(
                            type=openapi.TYPE_INTEGER, example=4
                        ),
                        "previous_page": openapi.Schema(
                            type=openapi.TYPE_INTEGER, example=2
                        ),
                    },
                ),
            },
        )

        return paged_schema
