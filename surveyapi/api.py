"""
api.py
- provides the API endpoints for consuming and producing
  REST requests and responses
"""
import json
import traceback
from functools import wraps
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request, current_app, g

import jwt

from .models import db, Survey, Question, Choice, User, UserSurveyHistory

api = Blueprint('api', __name__)


def token_required(f):
    @wraps(f)
    def _verify(*args, **kwargs):
        auth_headers = request.headers.get('Authorization', '').split()

        invalid_msg = {
            'message': 'Invalid token. Registeration and / or authentication required',
            'authenticated': False
        }
        expired_msg = {
            'message': 'Expired token. Reauthentication required.',
            'authenticated': False
        }

        if len(auth_headers) != 2:
            return jsonify(invalid_msg), 401

        try:
            token = auth_headers[1]
            data = jwt.decode(token, current_app.config['SECRET_KEY'])
            print(data)
            user = User.query.filter_by(email=data['sub']).first()
            if not user:
                raise RuntimeError('User not found')
            return f(user, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify(expired_msg), 401  # 401 is Unauthorized HTTP status code
        except (jwt.InvalidTokenError, Exception) as e:
            print(traceback.format_exc())
            return jsonify(invalid_msg), 401

    return _verify


@api.route('/register/', methods=['POST'])
def register():
    data = request.get_json()
    user = User(**data)
    db.session.add(user)
    db.session.commit()
    return jsonify(user.to_dict()), 201


@api.route('/login/', methods=('POST',))
def login():
    data = request.get_json()
    user = User.authenticate(**data)

    if not user:
        return jsonify({'message': 'Invalid credentials', 'authenticated': False}), 401

    token = jwt.encode({
        'sub': user.email,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(minutes=30)},
        current_app.config['SECRET_KEY'])
    return jsonify({'token': token.decode('UTF-8'), 'user_id': user.id})


@api.route('/surveys/', methods=['POST'])
@token_required
def create_survey(current_user):
    data = request.get_json()
    print(data)
    survey = Survey(name=data['name'])
    questions = []
    for q in data['questions']:
        question = Question(text=q['question'])
        question.choices = []
        for c in q['choices']:
            c_t, c_s = c.split('=')
            question.choices.append(Choice(text=c_t, score=int(c_s)))
        questions.append(question)
    survey.questions = questions
    survey.creator = current_user
    db.session.add(survey)
    db.session.commit()
    return jsonify(survey.to_dict()), 201


@api.route('/surveys/', methods=['GET'])
def fetch_surveys():
    surveys = Survey.query.all()
    return jsonify([s.to_dict() for s in surveys])


@api.route('/surveys/<int:suvery_id>/', methods=['GET', 'PUT'])
@token_required
def survey(current_user, suvery_id):
    survey = Survey.query.get(suvery_id)
    if request.method == 'GET':
        return jsonify(survey.to_dict())
    elif request.method == 'PUT':
        data = request.get_json()
        choice_list = dict()
        score = 0
        survey.viewed += 1
        for q in data['questions']:
            choice = Choice.query.get(q['choice'])
            choice.selected = choice.selected + 1
            score += choice.score
            print(choice.id, choice.selected)
            choice_list[choice.question_id] = choice.id
        ush = UserSurveyHistory(user_id=current_user.id,
                                survey_id=suvery_id,
                                score=score,
                                choice_list=json.dumps(choice_list),
                                user=current_user)
        db.session.add(ush)
        db.session.commit()
        survey = Survey.query.get(data['id'])
        return jsonify(survey.to_dict()), 201


@api.route('/user_surveys', methods=['GET'])
@api.route('/user_surveys/<int:user_id>/', methods=['POST'])
@token_required
def user_survey(current_user, user_id):
    if request.method == 'POST' and user_id == current_user.id:
        ush_list = current_user.historys
        res_list = []
        for ush in ush_list:
            res_list.append({'id': ush.id,
                             'survey_name': ush.survey.name,
                             'survey_id': ush.survey.id,
                             'choice_list': ush.choice_list,
                             'viewed_at': ush.viewed_at.strftime("%Y-%m-%d %H:%M:%S"),
                             'score': ush.score})
        return jsonify(res_list), 201
    else:
        return {}, 201
    # return jsonify({'message': 'Unable to check others score', 'authenticated': True}), 401
