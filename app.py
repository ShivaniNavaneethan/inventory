from flask import Flask, render_template, request, redirect, url_for, flash, send_file, make_response, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pandas as pd
import os
from werkzeug.security import generate_password_hash, check_password_hash
from xhtml2pdf import pisa
from io import BytesIO
import datetime
from flask_migrate import Migrate
import plotly.graph_objs as go
from markupsafe import Markup

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_default_dev_key')
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class Component(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), nullable=False)  # used, unused, defect
    location = db.Column(db.String(100))
    purchase_date = db.Column(db.String(20))
    notes = db.Column(db.Text)
    purpose = db.Column(db.String(200))
    used_by_for = db.Column(db.String(100))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.context_processor
def inject_now():
    return {'now': datetime.datetime.utcnow()}

with app.app_context():
    db.create_all()

@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('register'))
        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Logged in successfully.')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.')
    return redirect(url_for('login'))

@app.route('/inventory')
@login_required
def inventory():
    all_components = Component.query.all()
    navabarath_components = Component.query.filter(Component.location.ilike('%navabarath%')).all()
    
    navabarath_ids = {c.id for c in navabarath_components}
    livestock_components = [c for c in all_components if c.id not in navabarath_ids]
    
    return render_template(
        'inventory.html', 
        livestock_components=livestock_components,
        navabarath_components=navabarath_components
    )

@app.route('/navabarath')
@login_required
def navabarath():
    navabarath_components = Component.query.filter(Component.location.ilike('%navabarath%')).all()
    return render_template('navabarath.html', navabarath_components=navabarath_components)

@app.route('/companion_robot')
@login_required
def companion_robot():
    companion_robot_components = Component.query.filter(Component.location.ilike('%companion robot%')).all()
    return render_template('companion_robot.html', companion_robot_components=companion_robot_components)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_component():
    if request.method == 'POST':
        name = request.form['name']
        type_ = request.form['type']
        quantity = int(request.form['quantity'])
        status = request.form['status']
        # Handle new location logic
        location_select = request.form.get('location_select')
        location = None
        if location_select == 'other':
            location = request.form.get('location', '').strip()
        else:
            location = location_select
        if not location:
            flash('Location is required. Please select or enter a location.')
            return render_template('add_component.html')
        purchase_date = request.form['purchase_date']
        notes = request.form['notes']
        purpose = request.form['purpose']
        used_by_for = request.form['used_by_for']
        new_component = Component(
            name=name, type=type_, quantity=quantity, status=status,
            location=location, purchase_date=purchase_date, notes=notes,
            purpose=purpose, used_by_for=used_by_for
        )
        db.session.add(new_component)
        db.session.commit()
        flash('Component added successfully!')
        # Redirect based on location
        if 'navabarath' in location.lower():
            return redirect(url_for('navabarath'))
        else:
            return redirect(url_for('inventory'))
    return render_template('add_component.html')

@app.route('/edit/<int:component_id>', methods=['GET', 'POST'])
@login_required
def edit_component(component_id):
    component = Component.query.get_or_404(component_id)
    if request.method == 'POST':
        component.name = request.form['name']
        component.type = request.form['type']
        component.quantity = int(request.form['quantity'])
        component.status = request.form['status']
        component.location = request.form['location']
        component.purchase_date = request.form['purchase_date']
        component.notes = request.form['notes']
        component.purpose = request.form['purpose']
        component.used_by_for = request.form['used_by_for']
        db.session.commit()
        flash('Component updated successfully!')
        return redirect(url_for('inventory'))
    return render_template('edit_component.html', component=component)

@app.route('/delete/<int:component_id>', methods=['POST'])
@login_required
def delete_component(component_id):
    component = Component.query.get_or_404(component_id)
    db.session.delete(component)
    db.session.commit()
    flash('Component deleted successfully!')
    return redirect(url_for('inventory'))

@app.route('/export_csv')
@login_required
def export_csv():
    name = request.args.get('name', '').strip()
    type_ = request.args.get('type', '').strip()
    status = request.args.get('status', '').strip()
    query = Component.query
    if name:
        query = query.filter(Component.name.ilike(f'%{name}%'))
    if type_:
        query = query.filter(Component.type.ilike(f'%{type_}%'))
    if status:
        query = query.filter(Component.status == status)
    components = query.all()
    data = [{
        'ID': c.id,
        'Name': c.name,
        'Type': c.type,
        'Quantity': c.quantity,
        'Status': c.status,
        'Location': c.location,
        'Purchase Date': c.purchase_date,
        'Notes': c.notes
    } for c in components]
    df = pd.DataFrame(data)
    csv_path = 'inventory_export.csv'
    df.to_csv(csv_path, index=False)
    return send_file(csv_path, as_attachment=True)

@app.route('/export_pdf')
@login_required
def export_pdf():
    name = request.args.get('name', '').strip()
    type_ = request.args.get('type', '').strip()
    status = request.args.get('status', '').strip()
    query = Component.query
    if name:
        query = query.filter(Component.name.ilike(f'%{name}%'))
    if type_:
        query = query.filter(Component.type.ilike(f'%{type_}%'))
    if status:
        query = query.filter(Component.status == status)
    components = query.all()
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
    rendered = render_template('inventory_pdf.html', components=components, now=now)
    pdf = BytesIO()
    pisa_status = pisa.CreatePDF(rendered, dest=pdf)
    if pisa_status.err:
        return 'PDF generation failed', 500
    pdf.seek(0)
    return send_file(pdf, mimetype='application/pdf', as_attachment=True, download_name='inventory_report.pdf')

@app.route('/inventory_analysis')
@login_required
def inventory_analysis():
    components = Component.query.all()
    names = [c.name for c in components]
    quantities = [c.quantity for c in components]
    bar = go.Bar(x=names, y=quantities)
    layout = go.Layout(title='Inventory Quantities by Component', xaxis=dict(title='Component Name'), yaxis=dict(title='Quantity'))
    fig = go.Figure(data=[bar], layout=layout)
    graph_html = fig.to_html(full_html=False, include_plotlyjs='cdn')
    return render_template('inventory_analysis.html', graph_html=Markup(graph_html))

if __name__ == '__main__':
    app.run() 