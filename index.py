from flask import Flask, render_template 

app = Flask(__name__)

@app.route('/')
def principal():
    return render_template('menu.html')

@app.route('/log-al')
def logalum():
    return render_template('Login-ALUM.html')

@app.route('/log-PRO')
def logpro():
    return render_template('Login-Pro.html')

if __name__ == '__main__':
    app.run(debug=True, port=3500)