import io

from django.contrib.auth import get_user_model
from django.db.models.aggregates import Count, Sum
from django.db.models.expressions import Exists, OuterRef, Value
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from rest_framework import generics, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import (SAFE_METHODS, AllowAny,
                                        IsAuthenticated,
                                        IsAuthenticatedOrReadOnly)
from rest_framework.response import Response

from api.filters import IngredientFilter, RecipeFilter
from api.permissions import IsAdminOrReadOnly
from recipes.models import (FavoriteRecipe, Ingredient, Recipe, ShoppingCart,
                            Subscribe, Tag)

from .serializers import (IngredientSerializer, RecipeReadSerializer,
                          RecipeWriteSerializer, SubscribeRecipeSerializer,
                          SubscribeSerializer, TagSerializer)

User = get_user_model()
FILENAME = 'shoppingcart.pdf'


class GetObjectMixin:
    """Миксин для удаления/добавления рецептов избранных/корзины."""

    serializer_class = SubscribeRecipeSerializer
    permission_classes = (AllowAny,)

    def get_object(self):
        recipe_id = self.kwargs['recipe_id']
        recipe = get_object_or_404(Recipe, id=recipe_id)
        self.check_object_permissions(self.request, recipe)
        return recipe


class PermissionAndPaginationMixin:
    """Миксин для списка тегов и ингридиентов."""

    permission_classes = (IsAdminOrReadOnly,)
    pagination_class = None


class AddAndDeleteSubscribe(
        generics.RetrieveDestroyAPIView,
        generics.ListCreateAPIView):
    """Подписка и отписка от пользователя."""

    serializer_class = SubscribeSerializer

    def get_queryset(self):
        return self.request.user.follower.select_related(
            'following'
        ).prefetch_related(
            'following__recipe'
        ).annotate(
            recipes_count=Count('following__recipe'),
            is_subscribed=Value(True), )

    def get_object(self):
        user_id = self.kwargs['user_id']
        user = get_object_or_404(User, id=user_id)
        self.check_object_permissions(self.request, user)
        return user

    def create(self, request, *args, **kwargs):
        instance = self.get_object()
        if request.user.id == instance.id:
            return Response(
                {'errors': 'На самого себя не подписаться!'},
                status=status.HTTP_400_BAD_REQUEST)
        if request.user.follower.filter(author=instance).exists():
            return Response(
                {'errors': 'Уже подписан!'},
                status=status.HTTP_400_BAD_REQUEST)
        subs = request.user.follower.create(author=instance)
        serializer = self.get_serializer(subs)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def perform_destroy(self, instance):
        self.request.user.follower.filter(author=instance).delete()


class AddDeleteFavoriteRecipe(
        GetObjectMixin,
        generics.RetrieveDestroyAPIView,
        generics.ListCreateAPIView):
    """Добавление и удаление рецепта в/из избранных."""

    def create(self, request, *args, **kwargs):
        instance = self.get_object()
        request.user.favorite_recipe.recipe.add(instance)
        serializer = self.get_serializer(instance)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def perform_destroy(self, instance):
        self.request.user.favorite_recipe.recipe.remove(instance)


class AddDeleteShoppingCart(
        GetObjectMixin,
        generics.RetrieveDestroyAPIView,
        generics.ListCreateAPIView):
    """Добавление и удаление рецепта в/из корзины."""

    def create(self, request, *args, **kwargs):
        instance = self.get_object()
        request.user.shopping_cart.recipe.add(instance)
        serializer = self.get_serializer(instance)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def perform_destroy(self, instance):
        self.request.user.shopping_cart.recipe.remove(instance)


class RecipesViewSet(viewsets.ModelViewSet):
    """Рецепты."""

    filterset_class = RecipeFilter
    filterset_fields = ['is_favorited', 'is_in_shopping_cart']
    permission_classes = (IsAuthenticatedOrReadOnly,)

    def get_serializer_class(self):
        if self.request.method in SAFE_METHODS:
            return RecipeReadSerializer
        return RecipeWriteSerializer

    def get_queryset(self):
        return Recipe.objects.annotate(
            is_favorited=Exists(
                FavoriteRecipe.objects.filter(
                    user=self.request.user, recipe=OuterRef('id'))),
            is_in_shopping_cart=Exists(
                ShoppingCart.objects.filter(
                    user=self.request.user,
                    recipe=OuterRef('id')))
        ).select_related('author').prefetch_related(
            'tags', 'ingredients', 'recipe',
            'shopping_cart', 'favorite_recipe'
        ) if self.request.user.is_authenticated else Recipe.objects.annotate(
            is_in_shopping_cart=Value(False),
            is_favorited=Value(False),
        ).select_related('author').prefetch_related(
            'tags', 'ingredients', 'recipe',
            'shopping_cart', 'favorite_recipe')

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)

    @action(
        detail=False,
        methods=['get'],
        permission_classes=(IsAuthenticated,))
    def download_shopping_cart(self, request):
        """Качаем список с ингредиентами."""

        # buffer = io.BytesIO()
        # page = canvas.Canvas(buffer)
        # pdfmetrics.registerFont(TTFont('Vera', 'Vera.ttf'))
        # x_position, y_position = 50, 800
        shopping_cart = (
            request.user.shopping_cart.recipe.
            values(
                'ingredients__name',
                'ingredients__measurement_unit'
            ).annotate(amount=Sum('recipe__amount')).order_by())
        # page.setFont('Vera', 14)
        data = ''
        if shopping_cart:
            # indent = 20
            # page.drawString(x_position, y_position, 'Cписок покупок:')
            # for index, recipe in enumerate(shopping_cart, start=1):
            #     page.drawString(
            #         x_position, y_position - indent,
            #         f'{index}. {recipe["ingredients__name"]} - '
            #         f'{recipe["amount"]} '
            #         f'{recipe["ingredients__measurement_unit"]}.')
            #     y_position -= 15
            #     if y_position <= 50:
            #         page.showPage()
            #         y_position = 800
            # page.save()
            # buffer.seek(0)
            # return FileResponse(
            #     buffer, charset='utf-8', as_attachment=True, filename=FILENAME)
            for index, recipe in enumerate (shopping_cart):
                data += (f'{index}. {recipe["ingredients__name"]} - '
                         f'{recipe["amount"]} '
                         f'{recipe["ingredients__measurement_unit"]}.')
        else:
            data = 'Список покупок пуст'
        return HttpResponse(
            data,
            content_type="text/plain, charset=utf8",
            headers={"Content-Disposition": "attachment; filename=shopping_cart.txt"},
        )
        # page.setFont('Vera', 24)
        # page.drawString(
        #     x_position,
        #     y_position,
        #     'Cписок покупок пуст!')
        # page.save()
        # buffer.seek(0)
        # return FileResponse(buffer, charset='utf-8',
        #                     as_attachment=True, filename=FILENAME)


class TagsViewSet(
        PermissionAndPaginationMixin,
        viewsets.ModelViewSet):
    """Список тэгов."""

    queryset = Tag.objects.all()
    serializer_class = TagSerializer


class IngredientsViewSet(
        PermissionAndPaginationMixin,
        viewsets.ModelViewSet):
    """Список ингредиентов."""

    queryset = Ingredient.objects.all()
    serializer_class = IngredientSerializer
    filterset_class = IngredientFilter


class SubscriptionsView(generics.ListAPIView):
    serializer_class = SubscribeSerializer

    def get_queryset(self):
        user = self.request.user
        return Subscribe.objects.filter(user=user)
