from sqlalchemy import Column, Integer, String, create_engine, Date
from sqlalchemy.orm import declarative_base, sessionmaker
from flask import Flask, request, jsonify
from datetime import datetime
import uuid

#base = declarative_base()
#creating engine
engine = create_engine("sqlite:///onb.db")

#Added comment 123 by m1
from sqlalchemy import Column, Integer, String, Float, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
import bcrypt

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    user_id = Column(String, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)  # Hashed password
    portfolios = relationship("Portfolio", back_populates="user")
    tokens = relationship("AccessToken", back_populates="user")
    performances = relationship("InvestmentPerformance", back_populates="user")

class AccessToken(Base):
    __tablename__ = 'access_tokens'
    id = Column(Integer, primary_key=True, autoincrement=True)
    token = Column(String, unique=True, nullable=False) #unique = true
    user_id = Column(String, ForeignKey('users.user_id'))
    expiration = Column(DateTime, nullable=False)
    user = relationship("User", back_populates="tokens")

class Portfolio(Base):
    __tablename__ = 'portfolios'
    portfolio_id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey('users.user_id'))
    portfolio_name = Column(String)
    total_value = Column(Float)
    currency = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="portfolios")
    asset_allocations = relationship("AssetAllocation", back_populates="portfolio")
    performances = relationship("InvestmentPerformance", back_populates="portfolio")

class AssetAllocation(Base):
    __tablename__ = 'asset_allocations'
    asset_id = Column(Integer, primary_key=True, autoincrement=True)
    portfolio_id = Column(String, ForeignKey('portfolios.portfolio_id'))
    asset_type = Column(String)
    allocation_percentage = Column(Float)
    current_value = Column(Float)

    portfolio = relationship("Portfolio", back_populates="asset_allocations")

# Investment Performance Model
class InvestmentPerformance(Base):
    __tablename__ = 'investment_performances'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String, ForeignKey('users.user_id'))
    portfolio_id = Column(String, ForeignKey('portfolios.portfolio_id'))
    total_return_value = Column(Float)
    total_return_percentage = Column(Float)
    currency = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="performances")
    portfolio = relationship("Portfolio", back_populates="performances")
    performance_breakdown = relationship("PerformanceBreakdown", back_populates="performance", uselist=False)

# Performance Breakdown Model
class PerformanceBreakdown(Base):
    __tablename__ = 'performance_breakdowns'
    id = Column(Integer, primary_key=True, autoincrement=True)
    performance_id = Column(Integer, ForeignKey('investment_performances.id'))
    asset_type = Column(String)
    current_value = Column(Float)
    return_percentage = Column(Float)

    performance = relationship("InvestmentPerformance", back_populates="performance_breakdown")

Base.metadata.create_all(engine)

Session = sessionmaker(bind=engine)

session = Session()

# Default User Data
password = "password123"
password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# Check if the user already exists
default_user = session.query(User).filter_by(username="madhavi").first()
if not default_user:
    default_user = User(user_id="123456789", username="madhavi", password_hash=password_hash)
    session.add(default_user)
    session.commit()  # Commit after adding user
else:
    print("User already exists.")

# Default Portfolio Data
default_portfolio = session.query(Portfolio).filter_by(portfolio_id="987654321").first()
if not default_portfolio:
    default_portfolio = Portfolio(
        portfolio_id="987654321",
        portfolio_name="Retirement Portfolio",
        total_value=125000.00,
        currency="USD",
        timestamp=datetime.utcnow(),
        user=default_user
    )
    session.add(default_portfolio)
    session.commit()  # Commit after adding portfolio
else:
    print("Portfolio already exists.")

# Default Asset Allocation
default_asset_allocation = session.query(AssetAllocation).filter_by(portfolio_id="987654321").first()
if not default_asset_allocation:
    default_asset_allocation = AssetAllocation(
        asset_type="Stocks",
        allocation_percentage=60.0,
        current_value=75000.00,
        portfolio=default_portfolio
    )
    session.add(default_asset_allocation)
    session.commit()  # Commit after adding asset allocation
else:
    print("Asset allocation already exists.")


# Create Investment Performance Data
investment_performance = session.query(InvestmentPerformance).filter_by(portfolio_id="987654321").first()
if not investment_performance:
    investment_performance = InvestmentPerformance(
        user_id=default_user.user_id,
        portfolio_id=default_portfolio.portfolio_id,
        total_return_value=20000.00,
        total_return_percentage=19.0,
        currency="USD",
        timestamp=datetime.utcnow()
    )
    session.add(investment_performance)
    session.commit()

# Create Performance Breakdown for Stocks
performance_breakdown = session.query(PerformanceBreakdown).filter_by(performance_id=investment_performance.id).first()
if not performance_breakdown:
    performance_breakdown = PerformanceBreakdown(
        performance_id=investment_performance.id,
        asset_type="Stocks",
        current_value=75000.00,
        return_percentage=15.4
    )
    session.add(performance_breakdown)
    session.commit()

app = Flask(__name__)

# Generate Access Token
def generate_access_token(user_id):
    token = str(uuid.uuid4())  # Generate a unique token
    expiration = datetime.utcnow() + timedelta(hours=1)

    new_token = AccessToken(token=token, user_id=user_id, expiration=expiration)
    session.add(new_token)
    try:
        session.commit()  # Commit here to catch duplicate token issues
    except:
        session.rollback()  # Rollback in case of duplicate token error
        print("Duplicate token detected, generating a new one.")
        return generate_access_token(user_id)  # Retry with a new token

    return token

# Validate Token
def validate_token(token):
    session.expire_all()
    access_token = session.query(AccessToken).filter_by(token=token).first()
    if access_token and access_token.expiration > datetime.utcnow():
        return access_token.user_id
    return None

@app.before_request
def clean_session():
    session.expire_all()

# Login API (With Username & Password)
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    user = session.query(User).filter_by(username=username).first()

    if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    token = generate_access_token(user.user_id)
    return jsonify({
        "status": "success",
        "access_token": token,
        "expires_at": datetime.utcnow() + timedelta(hours=1)  # 10 years validity
    }), 200


# POST API
@app.route('/api/portfolios', methods=['GET'])
def get_portfolio():

    # Get the Authorization header
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"status": "error", "message": "Missing Authorization header"}), 401
    
    # Strip "Bearer " from the header
    parts = auth_header.split() # Bearer asdffgbbhnn
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return jsonify({"status": "error", "message": "Invalid Authorization header format"}), 401

    token = parts[1]  # The actual token part

    # Validate the token
    user_id = validate_token(token)
    if not user_id:
        return jsonify({"status": "error", "message": "Invalid or expired token"}), 401


    portfolio = session.query(Portfolio).filter_by(user_id=user_id).first()
    if not portfolio:
        return jsonify({"status": "error", "message": "Portfolio not found"}), 404
    
    asset_allocations = session.query(AssetAllocation).filter_by(portfolio_id=portfolio.portfolio_id).all()
    if not asset_allocations:
        return jsonify({"status": "error", "message": "assets not found"}), 404
    
     # Prepare asset allocation data
    assets_data = [
        {
            "id": asset.asset_id,
            "asset_type": asset.asset_type,
            "allocation_percentage": asset.allocation_percentage,
            "current_value": asset.current_value
        }
        for asset in asset_allocations
    ]
    
    return jsonify({
        "status": "success",
        "data": {
            "portfolio_id": portfolio.portfolio_id,
            "portfolio_name": portfolio.portfolio_name,
            "total_value": {
                "currency": portfolio.total_value,
                "value": portfolio.currency
            },
            "timestamp": portfolio.timestamp.isoformat(),
            "asset_allocations": assets_data
        }
    }), 201

#@app.route('/api/investment-performance', methods=['POST'])
@app.route('/api/investment-performance', methods=['GET'])
def get_investment_performance():
    # Get the Authorization header
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"status": "error", "message": "Missing Authorization header"}), 401

    # Strip "Bearer " from the header
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return jsonify({"status": "error", "message": "Invalid Authorization header format"}), 401

    token = parts[1]  # The actual token part

    # Validate the token
    user_id = validate_token(token)
    if not user_id:
        return jsonify({"status": "error", "message": "Invalid or expired token"}), 401

    # Extract portfolio_id from the request body
    # data = request.json
    # portfolio_id = data.get("portfolio_id")

    portfolio_id = request.args["portfolio_id"]
    if not portfolio_id:
        return jsonify({"status": "error", "message": "Missing portfolio_id in request body"}), 400

    # Query the performance data
    performance = session.query(InvestmentPerformance).filter_by(user_id=user_id, portfolio_id=portfolio_id).first()
    if not performance:
        return jsonify({"status": "error", "message": "Investment performance data not found"}), 404

    # Get performance breakdown
    breakdown = performance.performance_breakdown

    return jsonify({
        "status": "success",
        "message": "Investment performance data retrieved successfully",
        "data": {
            "user_id": performance.user_id,
            "portfolio_id": performance.portfolio_id,
            "total_return": {
                "currency": performance.currency,
                "value": performance.total_return_value,
                "percentage": performance.total_return_percentage
            },
            "performance_breakdown": {
                breakdown.asset_type: {
                    "current_value": breakdown.current_value,
                    "return_percentage": breakdown.return_percentage
                }
            }
        },
        "timestamp": performance.timestamp.isoformat()
    }), 200



if __name__ == '__main__':
    app.run(debug=True)
