#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import json
import threading
import time
from dateutil import parser
from datetime import datetime


lock = threading.Lock()
is_ordered = False
is_order_success = False
expected_price = 0
access_token = open('token.txt', 'r').read()


def api_cart_info(access_token, retries = 5):
	try:
		url = 'https://mapi.sendo.vn/mob/checkout/cart/travel'
		headers = {
			'Authorization': access_token,
			'User-Agent': 'com.sendo.buyer/v4.0'
		}
		return requests.get(url, headers=headers).json()
	except Exception as e:
		pass
		print e
		if retries == 0:
			return False
		return api_cart_info(access_token, retries - 1)

def api_product_detail(access_token, product_id, retries = 5):
	try:
		url = 'https://mapi.sendo.vn/mob_v2/product/%s/detail?version=variant' % product_id
		headers = {
			'Authorization': access_token,
			'User-Agent': 'com.sendo.buyer/v4.0'
		}
		return requests.get(url, headers=headers).json()
	except Exception as e:
		pass
		print e
		if retries == 0:
			return False
		return api_product_detail(access_token, product_id, retries - 1)

def api_delete_product(access_token, item_hash, retries = 5):
	try:
		url = 'https://mapi.sendo.vn/mob/cart/update-api/'
		headers = {
			'Authorization': access_token,
			'User-Agent': 'com.sendo.buyer/v4.0',
			'Content-Type': 'application/json'
		}
		data = {
			"list_hash_id":[item_hash],
			"key":"delete"
		}
		return requests.post(url, headers=headers, json=data).json()
	except Exception as e:
		pass
		print e
		if retries == 0:
			return False
		return api_delete_product(access_token, item_hash, retries - 1)

def api_add_product(access_token, shop_id, product_id, options, retries = 5):
	try:
		url = 'https://mapi.sendo.vn/mob/cart/add/'
		headers = {
			'Authorization': access_token,
			'User-Agent': 'com.sendo.buyer/v4.0',
			'Content-Type': 'application/json'
		}
		data = {
			"shop_id": shop_id,
			"qty": 1,
			"from_source": 3,
			"device_id": "f77cadb4-0630-3264-b838-95e45f106dbd",
			"buynow": 1,
			"source_info": "",
			"source_block_id": "FS_products",
			"product_id": product_id,
			"source_page_name": "",
			"source_url": "",
			"source_page_id": "FS_popular"
		}
		if options:
			data["options"] = options
		return requests.post(url, headers=headers, json=data).json()
	except Exception as e:
		pass
		print e
		if retries == 0:
			return False
		return api_add_product(access_token, shop_id, product_id, options, retries - 1)

def api_checkout_info(access_token, shop_id, item_hash, retries = 5):
	try:
		url = 'https://checkout-api.sendo.vn/checkout/info'
		headers = {
			'Authorization': access_token,
			'User-Agent': 'com.sendo.buyer/v4.0',
			'Content-Type': 'application/json'
		}
		data = {
			"shop_id": shop_id,
			"cookie_order_source": "1601876707.utmcsr=direct|utmccn=none|utmcmd=none|utmctr=|utmcct=|gclid=|fbclid=",
			"item_hash": item_hash,
			"current_voucher": {
				"is_shop_voucher": False,
				"enable_suggest_voucher": True
			},
			"sendo_platform": "Android",
			"device_id":"f77cadb4-0630-3264-b838-95e45f106dbd",
			"ignore_invalid_product": -1,
			"version": 3.6,
			"enable_suggest_last_payment": True,
			"is_agree_installment": True
		}
		return requests.post(url, headers=headers, json=data).json()
	except Exception as e:
		pass
		print e
		if retries == 0:
			return False
		api_checkout_info(access_token, shop_id, item_hash, retries - 1)

def api_save_order(access_token, shop_id, item_hash, current_address_id, current_carrier, current_payment_method, product_id, final_price, receive_email, promotion, retries = 5):
	try:
		url = 'https://checkout-api.sendo.vn/checkout/save-order'
		headers = {
			'Authorization': access_token,
			'User-Agent': 'com.sendo.buyer/v4.0',
			'Content-Type': 'application/json'
		}

		data = {
			"shop_id": shop_id,
			"cookie_order_source": "1601876707.utmcsr=direct|utmccn=none|utmcmd=none|utmctr=|utmcct=|gclid=|fbclid=",
			"current_address_id": current_address_id,
			"current_carrier": current_carrier,
			"current_payment_method": {"method": current_payment_method},
			"current_voucher": {
				"is_shop_voucher": False
			},
			"sendo_platform": "Android",
			"device_id": "f77cadb4-0630-3264-b838-95e45f106dbd",
			"product_hashes": [item_hash],
			"current_products": [{
				"product_id": product_id,
				"final_price": final_price,
				"hash": item_hash,
				"promotion": promotion
			}],
			"ignore_invalid_product": -1,
			"current_receive_email_info": {
				"receive_email": receive_email,
				"is_disable_suggest_email": True
			},
			"order_type": 1,
			"version": 3.6,
			"is_agree_installment": True
		}
		return requests.post(url, headers=headers, json=data).json()
	except Exception as e:
		pass
		print e
		if retries == 0:
			return False
		return api_save_order(access_token, shop_id, item_hash, current_address_id, current_carrier, current_payment_method, product_id, final_price, receive_email, promotion, retries - 1)


def print_carts(access_token):
	carts_info = api_cart_info(access_token)
	for cart in carts_info['carts']:
		for product in cart['products']:
			for data in product['data']:
				print '[*] ID:', data['id']
				print '[*] Name:', data['name']
				print '[*] Price:', data['final_price']
				print '[*] Quantity:', data['quantity']
				print '[*] Attributes:'
				for attr in data['attribute']:
					print '  [+] Option:', attr['name'], '(', attr['product_option'], ')'
					for value in attr['value']:
						print '    [-] Value:', value['name'], '(', value['product_option_id'], ')'
				print '[*] Hash:', data['hash_id']
				print '-----------------------------'

def empty_carts(access_token):
	carts_info = api_cart_info(access_token)
	for cart in carts_info['carts']:
		for product in cart['products']:
			for data in product['data']:
				print '[*] ID:', data['id']
				print '[*] Name:', data['name']
				print '[*] Price:', data['final_price']
				print '[*] Quantity:', data['quantity']
				print '[*] Attributes:'
				for attr in data['attribute']:
					print '  [+] Option:', attr['name'], '(', attr['product_option'], ')'
					for value in attr['value']:
						print '    [-] Value:', value['name'], '(', value['product_option_id'], ')'
				print '[*] Hash:', data['hash_id']
				delete_result = api_delete_product(access_token, data['hash_id'])
				print '[!] Delete:', json.dumps(delete_result)
				print '-----------------------------'

def add_product_to_cart(access_token, shop_id, product_id, options):
	add_result = api_add_product(access_token, shop_id, product_id, options)
	print '[*] Add to cart:', add_result['message']
	if add_result['error'] == True:
		return False
	print '[*] Hash:', add_result['data']['hash']
	return add_result['data']['hash']

def order(access_token, shop_id, item_hash, current_address_id, current_carrier, current_payment_method, product_id, final_price, receive_email, promotion):
	global is_order_success
	for loop_iter in range(100):
		if is_order_success:
			break
		save_order_result = api_save_order(access_token, shop_id, item_hash, current_address_id, current_carrier, current_payment_method, product_id, final_price, receive_email, promotion)
		if 'increment_id' in save_order_result:
			is_order_success = True
			print "[~] Order successfully!!!!!!!"
			exit()
			return True
		elif 'is_error' in save_order_result and save_order_result['is_error'] == True and save_order_result['errors']:
			for error in save_order_result['errors']:
				if 'message' in error:
					print '[!] Message:', error['message']
				else:
					print '[!] Error:', json.dumps(error)
		else:
			print json.dumps(save_order_result)



def print_checkout_info(access_token, shop_id, item_hash, loop=True):
	global expected_price
	global is_ordered
	for loop_iter in range(1000):
		try:
			checkout_info = api_checkout_info(access_token, shop_id, item_hash)
			# print json.dumps(checkout_info)
			print '####################################'
			print '[*] Checkout info:'
			data = checkout_info['data']
			current_address_id = data['customer_data']['current_address_id']
			receive_email = data['customer_data']['receive_email_info']['receive_email']
			products_checkout = data['products_checkout']

			print '[*] Total price:', products_checkout['total_price']

			for product in products_checkout['products']:
				print '  [+] ID:', product['product_id']
				print '  [+] Name:', product['name']
				print '  [+] Final price:', product['final_price']
				# if 'option_data' in product:
				# 	print '  [+] Options data:'
				# 	for option in product['option_data']:
				# 		print '    [-] Option:', option['name'], '=', option['value']
				# else:
				# 	print '  [+] No options'
				print '  [+] Hash:', product['hash']


			shipping_info = data['shipping_info']
			# list_carrier = shipping_info['list_carrier']
			# print '  [+] Shipping info:'
			# for carrier in list_carrier:
			# 	print '    [-] Code:', carrier['carrier_code']
			# 	print '    [-] Name:', carrier['carrier_name']
			# 	print '    [-] Fee:', carrier['delivery_fee']
			# 	print '        ------------'
			current_carrier = shipping_info['current_carrier']

			payment_info = data['payment_info']
			# list_payment = payment_info['list_payment']
			# print '  [+] Payment info:'
			# for payment in list_payment:
			# 	print '    [-] Name:', payment['payment_name']
			# 	print '    [-] Code:', payment['payment_code']
			# 	print '        ------------'


			current_payment_method = payment_info['current_payment_data']['method']

			total_info = data['total_info']
			print '  [+] Sub total:', total_info['sub_total']
			print '  [+] Delivery fee:', total_info['delivery_fee']
			print '  [+] Grand total:', total_info['grand_total']
			# total_summary = total_info['total_summary']
			# print '  [+] Summary:'
			# for info in total_summary:
			# 	print info['label'], ':', info['value']
			print '********************************'
			print ' [~] Final price:', product['final_price']
			if product['final_price'] == expected_price:
				with lock:
					if is_ordered:
						print "Already ordered, exiting..."
						return
					threads = [threading.Thread(target=order, args=(access_token, shop_id, item_hash, current_address_id, current_carrier, current_payment_method, product['product_id'], product['final_price'], receive_email, product['promotion'])) for i in range(20)]
					for t in threads:
						t.start()
					is_ordered = True
					print "[*] Checkout started!!!"
					break
			else:
				print "[!] Current price", product['final_price'], 'not equals expected price', expected_price
			if not loop:
				break
		except Exception as e:
			pass
			print e


def show_product_detail(access_token, product_id):
	detail = api_product_detail(access_token, product_id)
	widgets = detail['data']
	product_info = next(item for item in widgets if item['type'] == 'ProductInfoWidget')
	attribute_info = next(item for item in widgets if item['type'] == 'AttributeWidget')
	shop_info = next(item for item in widgets if item['type'] == 'ShopInfoWidget')

	print '[*] Name:', product_info['data']['name']
	print '[*] Final price:', product_info['data']['final_price']
	print '[*] Promotion percent:', str(product_info['data']['final_promotion_percent']) + '%'
	print '[*] Available quantity:', product_info['data']['quantity']

	variants = attribute_info['data']['variants']
	attributes = attribute_info['data']['attribute']

	if len(attributes) > 0:
		print '[*] Attributes:'
		for variant in variants:
			attribute_option = variant['attribute_option']
			attr = {}
			attr_desc = ''
			for attribute_id in attribute_option:
				attribute = next(item for item in attributes if str(item['attribute_id']) == attribute_id)
				options = attribute['value']
				option =  next(item for item in options if item['option_id'] == attribute_option[attribute_id])
				attr[attribute['product_option']] = [option['product_option_id']]
				attr_desc += option['value'] + ' - '
			print '    [>] Attribute:', attr_desc
			if 'flashdeal_price' in variant:
				print '  [+] Flashdeal price:', variant['flashdeal_price']
				print '  [+] Flashdeal quantity:', variant['flashdeal_quantity']
			else:
				print '  [!] No Flashdeal!!!'
			print '    [?]  ', json.dumps(attr)
			print '        ------------'
	else:
		print '[*] No attribute options'
	print '[*] Shop name:', shop_info['data']['shop_name']
	print '[*] Shop ID:', shop_info['data']['shop_id']
	return shop_info['data']['shop_id']


def select_product_attribute(access_token, product_id):
	global options
	global expected_price
	global shop_id
	detail = api_product_detail(access_token, product_id)
	widgets = detail['data']
	product_info = next(item for item in widgets if item['type'] == 'ProductInfoWidget')
	attribute_info = next(item for item in widgets if item['type'] == 'AttributeWidget')
	shop_info = next(item for item in widgets if item['type'] == 'ShopInfoWidget')

	print '[*] Name:', product_info['data']['name']
	print '[*] Final price:', product_info['data']['final_price']
	print '[*] Promotion percent:', str(product_info['data']['final_promotion_percent']) + '%'
	print '[*] Available quantity:', product_info['data']['quantity']

	variants = attribute_info['data']['variants']
	attributes = attribute_info['data']['attribute']

	if len(attributes) == 0:
		print '[*] No attribute options'
		expected_price = int(raw_input("Please enter expected_price: "))
		options = None
	else:
		print '[*] Attributes:'
		for i in range(len(variants)):
			variant = variants[i]
			attribute_option = variant['attribute_option']
			attr = {}
			attr_desc = ''
			for attribute_id in attribute_option:
				attribute = next(item for item in attributes if str(item['attribute_id']) == attribute_id)
				options = attribute['value']
				option =  next(item for item in options if item['option_id'] == attribute_option[attribute_id])
				attr[attribute['product_option']] = [option['product_option_id']]
				attr_desc += option['value'] + ' - '
			print '====[', i, '] Attribute:', attr_desc, '===='
			if 'flashdeal_price' in variant:
				print '  [+] Flashdeal price:', variant['flashdeal_price']
				print '  [+] Flashdeal quantity:', variant['flashdeal_quantity']
			else:
				print '  [!] No Flashdeal!!!'
			print '    [?]  ', json.dumps(attr)
			print '        ------------'
		
		attr_index = int(raw_input("Select attribute index: "))
		variant = variants[attr_index]
		expected_price = variant['flashdeal_price']

		if expected_price > 10000:
			expected_price = int(raw_input("Enter expected_price: "))


		attribute_option = variant['attribute_option']
		attr = {}
		attr_desc = ''
		for attribute_id in attribute_option:
			attribute = next(item for item in attributes if str(item['attribute_id']) == attribute_id)
			options = attribute['value']
			option =  next(item for item in options if item['option_id'] == attribute_option[attribute_id])
			attr[attribute['product_option']] = [option['product_option_id']]
			attr_desc += option['value'] + ' - '
		print '====[', attr_index, '] Attribute:', attr_desc, '===='

		options = attr


	print '[*] Shop name:', shop_info['data']['shop_name']
	print '[*] Shop ID:', shop_info['data']['shop_id']
	shop_id = shop_info['data']['shop_id']



def get_time_remain(access_token, product_id):
	detail = api_product_detail(access_token, product_id)
	widgets = detail['data']
	product_info = next(item for item in widgets if item['type'] == 'ProductInfoWidget')
	return product_info['data']['promotion_info']['time_remain']


product_id = int(raw_input("Enter product_id: "))
select_product_attribute(access_token, product_id)


print "[*] Selected attribute:", json.dumps(options)
print "[*] Selected expected_price:", expected_price

# shop_id = show_product_detail(access_token, product_id)
print "[*] Empty cart..."
empty_carts(access_token)
print "[*] Adding product..."
item_hash = add_product_to_cart(access_token, shop_id, product_id, options)
if not item_hash:
	exit()
print_checkout_info(access_token, shop_id, item_hash, False)
# final_price = 10000  # change it

# print '[*] Current address id:', current_address_id
# print '[*] Current carrier:', current_carrier
# print '[*] Current payment method:', current_payment_method
# print '[*] Final price:', final_price
# print '[*] Receive email:', receive_email
if options  == None:
	start_time = parser.parse(raw_input("Enter start time: "))
	time_remain = (start_time - datetime.now()).seconds - 2
else:
	time_remain = get_time_remain(access_token, product_id) - 2
print '[*] Time remain:', time_remain

# raw_input("Press enter to start...")
time.sleep(time_remain)



thread_count = 30
threads = [threading.Thread(target=print_checkout_info, args=(access_token, shop_id, item_hash)) for i in range(thread_count)]
for t in threads:
	t.start()
