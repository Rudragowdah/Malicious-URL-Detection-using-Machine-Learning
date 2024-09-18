from flask import Flask, render_template, request
from logic import check_url_status
app = Flask(__name__)  # initializing the Flask Class
# this is a flask app
@app.route("/")
@app.route("/home")
def home():
	return  render_template("index.html")       

@app.route("/result",methods = ['POST','GET'])
def result():
	output = request.form.to_dict()
	name = output["name"]
	res = check_url_status(name)
	out = ""
	if res[0] == -1:
		out = "URL is likely to be Phishing"
	elif res[0] == 1:
		out = "URL is likely to be Legitimate"
	out2 = []
	if out!="":
		out2.append(out)
		out2.append(res[1])
	else:
		out2 = out

	return render_template("index.html", name = out2)


if __name__=="__main__":
	app.run(debug=True,port=5001)