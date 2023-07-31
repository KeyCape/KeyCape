port module Main exposing (main)

import Browser
import Browser.Navigation as Nav
import Html exposing (..)
import Html.Attributes exposing (..)
import Html.Events exposing (onClick, onInput)
import Url exposing (Url)
import Url.Parser as P exposing ((</>), (<?>), Parser, s, top)
import Url.Parser.Query as Q



-- MAIN


main : Program () Model Msg
main =
    Browser.application
        { init = init
        , view = view
        , update = update
        , subscriptions = subscriptions
        , onUrlChange = UrlChanged
        , onUrlRequest = LinkClicked
        }



-- MODEL


type Route
    = Home
    | Admin
    | SignUp
    | SignIn


type alias Client =
    { username : String
    , isAdmin : Bool
    }


type alias RegisterForm =
    { username : String
    }


type alias LoginForm =
    { username : String
    }


type alias Model =
    { key : Nav.Key
    , url : Url.Url
    , route : Maybe Route
    , client : Maybe Client
    , registerForm : RegisterForm
    , loginForm : LoginForm
    , message : Maybe Message
    }


type alias Message =
    { msg : String
    , error : Bool
    }


init : () -> Url.Url -> Nav.Key -> ( Model, Cmd Msg )
init _ url key =
    ( Model key url (Just Home) Nothing { username = "" } { username = "" } Nothing, Cmd.none )



-- URL PARSING


routeParser : Parser (Route -> a) a
routeParser =
    P.oneOf
        [ P.map Home top
        , P.map Admin (P.s "admin")
        , P.map SignUp (P.s "register")
        , P.map SignIn (P.s "login")
        ]



-- UPDATE


type Msg
    = LinkClicked Browser.UrlRequest
    | UrlChanged Url.Url
    | Register
    | Login
    | Logout
    | RegisterUserNameChanged String
    | LoginUserNameChanged String
    | PortRegisterResultRecv Message
    | PortLoginResultRecv Message


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    let
        updateLoginName : LoginForm -> String -> LoginForm
        updateLoginName form username =
            { form | username = username }

        updateRegisterName : RegisterForm -> String -> RegisterForm
        updateRegisterName form username =
            { form | username = username }

        newModel : Model
        newModel =
            { model | message = Nothing }
    in
    case msg of
        LinkClicked urlRequest ->
            case urlRequest of
                Browser.Internal url ->
                    ( newModel, Nav.pushUrl newModel.key (Url.toString url) )

                Browser.External href ->
                    ( newModel, Nav.load href )

        UrlChanged url ->
            ( { newModel | url = url, route = P.parse routeParser url }, Cmd.none )

        Register ->
            ( newModel, sendRegister newModel.registerForm.username )

        Login ->
            ( newModel, sendLogin newModel.loginForm.username )

        Logout ->
            ( newModel, Cmd.none )

        RegisterUserNameChanged username ->
            ( { newModel | registerForm = updateRegisterName newModel.registerForm username }, Cmd.none )

        LoginUserNameChanged username ->
            ( { newModel | loginForm = updateLoginName newModel.loginForm username }, Cmd.none )

        PortRegisterResultRecv portResult ->
            ( { newModel | message = Just portResult }, Cmd.none )

        PortLoginResultRecv portResult ->
            ( { newModel | message = Just portResult }, Cmd.none )



-- SUBSCRIPTIONS


subscriptions : Model -> Sub Msg
subscriptions _ =
    Sub.batch [ recvLoginResult PortLoginResultRecv, recvRegisterResult PortRegisterResultRecv ]



-- PORTS


port sendRegister : String -> Cmd msg


port sendLogin : String -> Cmd msg


port recvRegisterResult : (Message -> msg) -> Sub msg


port recvLoginResult : (Message -> msg) -> Sub msg



-- VIEW


view : Model -> Browser.Document Msg
view model =
    { title = "App"
    , body =
        [ viewNav model
        , case model.message of
            Just message ->
                viewMessage message

            Nothing ->
                text ""
        , case model.route of
            Just Home ->
                viewLogin model.loginForm

            Just Admin ->
                text ""

            Just SignUp ->
                viewRegister model.registerForm

            Just SignIn ->
                viewLogin model.loginForm

            Nothing ->
                text ""
        ]
    }


viewLink : String -> String -> Html msg
viewLink name path =
    a [ class "nav-link", href path ] [ text name ]


viewNav : Model -> Html Msg
viewNav model =
    nav [ class "navbar", class "navbar-expand-lg", class "bg-body-tertiary", class "sticky-top" ]
        [ div [ class "container-fluid", class "container" ]
            [ a [ class "navbar-brand", href "/" ] [ text "KeyCape" ]
            , div [ class "collapse", class "navbar-collapse" ]
                [ div [ class "navbar-nav" ]
                    [ viewLink "Home" "/"
                    , viewLink "Admin" "/admin"
                    ]
                ]
            , div [ class "d-flex" ]
                [ case model.client of
                    Just client ->
                        span [ class "navbar-text" ] [ text "Welcome back ", span [ class "fw-bold", class "pe-2" ] [ text client.username ], button [ onClick Logout, class "btn", class "btn-secondary" ] [ text "Logout" ] ]

                    Nothing ->
                        viewLink "Login" "/login"
                ]
            ]
        ]


viewLogin : LoginForm -> Html Msg
viewLogin form =
    div [ class "container" ]
        [ div [ class "row", class "align-items-center", class "justify-content-center", style "height" "100vh" ]
            [ div [ class "card", class "text-center", class "p-3", style "width" "19em", class "bg-opacity-10", class "bg-white", class "border-0", style "box-shadow" "0px 0px 2px rgb(255 255 255 / 0.10)" ]
                [ div [ class "card-title", class "mb-2" ] [ h1 [ class "bi", class "bi-person-circle", class "display-2", class "position-absolute", class "top-0", class "start-50", class "translate-middle", class "rounded-circle", style "background-color" "#0c0c1c" ] [] ]
                , div [ class "card-body" ]
                    [ h1 [ class "pb-2" ] [ text "Sign in" ]
                    , p [ class "pb-2" ] [ text "Enter your username" ]
                    , div [ class "mb-5" ]
                        [ viewInput "input" "" form.username LoginUserNameChanged
                        , div [ class "form-text" ] [ text "Not a member? ", a [ class "primary-link", class "text-decoration-none", href "/register" ] [ text "Register" ] ]
                        ]
                    , div [ class "mb-2", class "d-grid" ]
                        [ button [ onClick Login, class "btn", style "background-color" "#2a4863" ] [ text "Login" ]
                        ]
                    ]
                ]
            ]
        ]


viewRegister : RegisterForm -> Html Msg
viewRegister form =
    div [ class "container" ]
        [ div [ class "row", class "align-items-center", class "justify-content-center", style "height" "100vh" ]
            [ div [ class "card", class "text-center", class "p-3", style "width" "19em", class "bg-opacity-10", class "bg-white", class "border-0", style "box-shadow" "0px 0px 2px rgb(255 255 255 / 0.10)" ]
                [ div [ class "card-title", class "mb-2" ] [ h1 [ class "bi", class "bi-person-circle", class "display-2", class "position-absolute", class "top-0", class "start-50", class "translate-middle", class "rounded-circle", style "background-color" "#0c0c1c" ] [] ]
                , div [ class "card-body" ]
                    [ h1 [ class "pb-2" ] [ text "Sign up" ]
                    , p [ class "pb-2" ] [ text "Enter your username" ]
                    , div [ class "mb-5" ]
                        [ viewInput "input" "" form.username RegisterUserNameChanged
                        , div [ class "form-text" ] [ text "Already a member? ", a [ class "primary-link", class "text-decoration-none", href "/login" ] [ text "Login" ] ]
                        ]
                    , div [ class "mb-2", class "d-grid" ]
                        [ button [ onClick Register, class "btn", style "background-color" "#2a4863" ] [ text "Register" ]
                        ]
                    ]
                ]
            ]
        ]


viewInput : String -> String -> String -> (String -> msg) -> Html msg
viewInput t p v toMsg =
    input [ type_ t, placeholder p, value v, onInput toMsg, class "form-control" ] []


viewMessage : Message -> Html msg
viewMessage msg =
    div [ class "alert", classList [ ( "alert-danger", msg.error ), ( "alert-success", not msg.error ) ], class "container", class "mt-2" ]
        [ text msg.msg
        ]
